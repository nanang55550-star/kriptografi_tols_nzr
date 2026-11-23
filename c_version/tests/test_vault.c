/* ==========================================================================
 * test_vault.c — unit test suite CRYPTO//GOD VAULT (C EDITION)
 * ==========================================================================
 * Framework mini sendiri (assert-based), tanpa dependensi eksternal --
 * cukup utk kebutuhan proyek ini & konsisten dgn filosofi "jangan tambah
 * dependensi kalau tidak perlu" yang dipakai di seluruh modul.
 *
 * Jalankan: make test   (atau langsung: ./bin/test_vault)
 * ========================================================================== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "../src/vault_format.h"
#include "../src/vault_api.h"
#include "../src/kdf.h"
#include "../src/crypto_core.h"
#include "../src/header_codec.h"
#include "../src/payload_iter.h"
#include "../src/compress.h"
#include "../src/password.h"
#include "../src/ratelimit.h"
#include "../src/base64.h"
#include "../src/util.h"

/* ---- Mini framework ----------------------------------------------------- */
static int g_pass = 0, g_fail = 0;
static const char *g_current = "";

#define TEST(name) static void name(void)
#define RUN(name) do { g_current = #name; printf("  %-52s", #name); fflush(stdout); \
                        int before = g_fail; name(); \
                        printf(g_fail == before ? "OK\n" : "FAIL\n"); } while (0)
#define CHECK(cond) do { \
    if (!(cond)) { \
        g_fail++; \
        printf("\n    [GAGAL] %s:%d: %s", __FILE__, __LINE__, #cond); \
    } else { g_pass++; } \
} while (0)
#define CHECK_EQ_INT(a, b) CHECK((a) == (b))
#define CHECK_STATUS_OK(st) CHECK((st) == GV_OK)
#define CHECK_STATUS_FAIL(st) CHECK((st) != GV_OK)

static const char *STRONG_PW = "Sup3rSecret!Passw0rd#2026";

/* ---- Direktori temp portable ---------------------------------------------
 * JANGAN hardcode "/tmp/..." -- di Termux/Android, /tmp umumnya TIDAK ada
 * atau tidak bisa ditulis aplikasi (Termux pakai $PREFIX/tmp via $TMPDIR).
 * mkstemp() thd path yang tak bisa ditulis akan gagal (return -1); kalau
 * fd itu dipakai ke fdopen()/fwrite() tanpa dicek, hasilnya FILE* NULL --
 * di Bionic libc (Android) itu di-abort paksa oleh FORTIFY_SOURCE. Jadi
 * dua lapis perbaikan di sini: (1) path yang benar2 portable, (2) setiap
 * pemakaian mkstemp() SELALU early-return kalau gagal, jangan cuma dicatat
 * lewat CHECK() lalu lanjut (CHECK() sengaja tidak menghentikan test agar
 * bisa akumulasi banyak gagal sekaligus -- makanya perlu guard manual utk
 * precondition yang kalau gagal bikin langkah berikutnya UB). */
static void gv_test_tmp_path(char *buf, size_t bufsize, const char *pattern) {
    const char *dir = getenv("TMPDIR");
    if (!dir || !dir[0]) dir = ".";  /* "." (CWD saat `make test` dijalankan) JAUH lebih
                                       * portable drpd asumsi "/tmp" ada & bisa ditulis --
                                       * di Android/Termux /tmp kerap TIDAK ADA sama sekali
                                       * (dikonfirmasi lewat pengujian di perangkat asli). */
    snprintf(buf, bufsize, "%s/%s", dir, pattern);
}

/* ========================================================================
 * Password validator
 * ======================================================================== */
TEST(test_password_too_short) {
    char reason[128];
    CHECK(gv_password_validate("Ab1!", reason, sizeof(reason)) == false);
}
TEST(test_password_missing_classes) {
    char reason[128];
    CHECK(gv_password_validate("lowercaseonlylong", reason, sizeof(reason)) == false);
}
TEST(test_password_strong_accepted) {
    char reason[128];
    CHECK(gv_password_validate(STRONG_PW, reason, sizeof(reason)) == true);
}
TEST(test_password_entropy_zero_for_empty) {
    CHECK(gv_password_entropy("") == 0.0);
}
TEST(test_password_generate_length_and_charset) {
    char buf[65];
    CHECK(gv_password_generate(buf, 64) == true);
    CHECK_EQ_INT(strlen(buf), 64u);
}
TEST(test_password_generate_distinct) {
    char a[33], b[33];
    gv_password_generate(a, 32);
    gv_password_generate(b, 32);
    CHECK(strcmp(a, b) != 0);
}

/* ========================================================================
 * Base64
 * ======================================================================== */
TEST(test_base64_roundtrip_various_lengths) {
    for (int len = 0; len <= 130; len++) {
        uint8_t data[130];
        for (int i = 0; i < len; i++) data[i] = (uint8_t)((i * 37 + 11) % 256);
        char *enc = gv_base64_encode(data, (size_t)len);
        CHECK(enc != NULL);
        size_t declen;
        uint8_t *dec = gv_base64_decode(enc, &declen);
        CHECK(dec != NULL);
        if (dec) {
            CHECK_EQ_INT(declen, (size_t)len);
            CHECK(len == 0 || memcmp(dec, data, (size_t)len) == 0);
        }
        free(enc); free(dec);
    }
}
TEST(test_base64_rejects_malformed) {
    const char *bad[] = {"abc", "ab=c", "====", "a===", "!!!!", "AB==CD==", NULL};
    for (int i = 0; bad[i]; i++) {
        size_t dl;
        uint8_t *d = gv_base64_decode(bad[i], &dl);
        CHECK(d == NULL);
        free(d);
    }
}

/* ========================================================================
 * KDF cross-validated (nilai referensi dihitung terpisah dgn Python
 * `cryptography`/`argon2-cffi` utk input yg sama -- lihat catatan commit).
 * ======================================================================== */
TEST(test_hkdf_matches_reference_vector) {
    uint8_t ikm[32], salt[32];
    for (int i = 0; i < 32; i++) { ikm[i] = (uint8_t)i; salt[i] = (uint8_t)(i + 100); }
    const char *info = "godvault-c-enc-key-v1";
    uint8_t okm[32];
    int ok = gv_hkdf_sha512(ikm, 32, salt, 32, (const uint8_t *)info, strlen(info), okm, 32);
    CHECK(ok == 1);
    static const uint8_t expected[32] = {
        0xeb,0xbe,0x98,0xfb,0xbc,0xc4,0x48,0x79,0x23,0x17,0x72,0x5d,0x6d,0x84,0xe0,0xe2,
        0x3c,0xf4,0x07,0xb2,0xba,0xdf,0x7c,0x40,0xc4,0x4d,0xec,0xc8,0x7c,0x7e,0x63,0xb7,
    };
    CHECK(memcmp(okm, expected, 32) == 0);
}

TEST(test_pbkdf2_matches_reference_vector) {
    gv_header_t hdr; memset(&hdr, 0, sizeof(hdr));
    for (int i = 0; i < GV_SALT_LEN; i++) hdr.salt[i] = (uint8_t)(i + 50);
    gv_kdf_default_params(&hdr, GV_KDF_PBKDF2);
    hdr.kdf_time_cost = 1000;
    uint8_t key[GV_KEY_LEN];
    gv_status_t st = gv_kdf_derive(&hdr, STRONG_PW, strlen(STRONG_PW), key);
    CHECK_STATUS_OK(st);
    static const uint8_t expected[32] = {
        0xf8,0xc3,0xa5,0x74,0xaf,0xfc,0x46,0x95,0x83,0x56,0x7a,0x4d,0xb5,0x62,0xad,0xa0,
        0xd9,0x67,0xb8,0x17,0x83,0x69,0xc4,0x19,0xda,0xe4,0x5e,0x22,0x59,0x6e,0xb8,0x0e,
    };
    CHECK(memcmp(key, expected, 32) == 0);
}

#ifdef GV_WITH_ARGON2
TEST(test_argon2id_matches_reference_vector) {
    gv_header_t hdr; memset(&hdr, 0, sizeof(hdr));
    for (int i = 0; i < GV_SALT_LEN; i++) hdr.salt[i] = (uint8_t)(i + 50);
    gv_kdf_default_params(&hdr, GV_KDF_ARGON2ID);
    hdr.kdf_time_cost = 2; hdr.kdf_mem_cost = 8192; hdr.kdf_parallelism = 1;
    uint8_t key[GV_KEY_LEN];
    gv_status_t st = gv_kdf_derive(&hdr, STRONG_PW, strlen(STRONG_PW), key);
    CHECK_STATUS_OK(st);
    static const uint8_t expected[32] = {
        0xaf,0x6d,0x9e,0x54,0x9b,0x0d,0x5a,0xec,0x82,0x77,0x2c,0x37,0xfb,0x97,0xaa,0xae,
        0xd9,0xd4,0xcc,0xe4,0x88,0x55,0xd5,0x6d,0x93,0x53,0xb2,0x2d,0xf1,0xab,0x43,0x6e,
    };
    CHECK(memcmp(key, expected, 32) == 0);
}
#endif

/* ========================================================================
 * AES-256-GCM primitif
 * ======================================================================== */
TEST(test_aes_gcm_roundtrip_and_tamper) {
    uint8_t key[GV_KEY_LEN], nonce[GV_NONCE_LEN];
    for (int i = 0; i < GV_KEY_LEN; i++) key[i] = (uint8_t)(i + 1);
    for (int i = 0; i < GV_NONCE_LEN; i++) nonce[i] = (uint8_t)(i + 200);
    const char *aad = "aad-test";
    const char *pt = "rahasia AES-GCM";
    size_t pt_len = strlen(pt);

    uint8_t ct[64], tag[GV_GCM_TAG_LEN], dec[64];
    CHECK(gv_aes_gcm_encrypt(key, nonce, (const uint8_t *)aad, strlen(aad),
                              (const uint8_t *)pt, pt_len, ct, tag) == 1);
    CHECK(gv_aes_gcm_decrypt(key, nonce, (const uint8_t *)aad, strlen(aad),
                              ct, pt_len, tag, dec) == 1);
    CHECK(memcmp(dec, pt, pt_len) == 0);

    ct[0] ^= 0xFF;
    CHECK(gv_aes_gcm_decrypt(key, nonce, (const uint8_t *)aad, strlen(aad),
                              ct, pt_len, tag, dec) == 0);
    ct[0] ^= 0xFF;

    tag[0] ^= 0xFF;
    CHECK(gv_aes_gcm_decrypt(key, nonce, (const uint8_t *)aad, strlen(aad),
                              ct, pt_len, tag, dec) == 0);
}

/* ========================================================================
 * Payload iterator (chunking + kompresi streaming)
 * ======================================================================== */
static int payload_roundtrip(const uint8_t *data, size_t len, int compress,
                              size_t chunk_size, size_t read_block) {
    FILE *in = tmpfile();
    if (len) fwrite(data, 1, len, in);
    rewind(in);

    gv_payload_iter_t it;
    if (!gv_payload_iter_init(&it, in, compress, chunk_size, read_block)) { fclose(in); return 0; }

    gv_buf_t collected; gv_buf_init(&collected);
    const uint8_t *piece; size_t plen; int is_last;
    int saw_last = 0;
    while (gv_payload_iter_next(&it, &piece, &plen, &is_last)) {
        gv_buf_append(&collected, piece, plen);
        if (is_last) { saw_last = 1; break; }
    }
    int no_error = !it.error;

    int ok;
    if (compress) {
        FILE *out = tmpfile();
        gv_inflate_t inf; gv_inflate_init(&inf);
        gv_inflate_feed(&inf, collected.data, collected.len, out);
        gv_inflate_free(&inf);
        fseek(out, 0, SEEK_END); long osz = ftell(out); rewind(out);
        uint8_t *res = (uint8_t *)malloc(osz > 0 ? (size_t)osz : 1);
        size_t rgot = fread(res, 1, (size_t)osz, out);
        (void)rgot;
        fclose(out);
        ok = ((size_t)osz == len) && (len == 0 || memcmp(res, data, len) == 0);
        free(res);
    } else {
        ok = (collected.len == len) && (len == 0 || memcmp(collected.data, data, len) == 0);
    }

    gv_buf_free(&collected);
    gv_payload_iter_free(&it);
    fclose(in);
    return ok && saw_last && no_error;
}

TEST(test_payload_iter_empty) {
    uint8_t d[1];
    CHECK(payload_roundtrip(d, 0, 0, 4096, 1024) == 1);
    CHECK(payload_roundtrip(d, 0, 1, 4096, 1024) == 1);
}
TEST(test_payload_iter_exact_chunk_boundary) {
    uint8_t d[4096];
    for (int i = 0; i < 4096; i++) d[i] = (uint8_t)(i * 7);
    CHECK(payload_roundtrip(d, 4096, 0, 4096, 1024) == 1);
}
TEST(test_payload_iter_multi_chunk) {
    size_t n = 500000;
    uint8_t *d = (uint8_t *)malloc(n);
    srand(7);
    for (size_t i = 0; i < n; i++) d[i] = (uint8_t)rand();
    CHECK(payload_roundtrip(d, n, 0, 4096, 8192) == 1);
    free(d);
}
TEST(test_payload_iter_multi_chunk_compressed) {
    size_t n = 500000;
    uint8_t *d = (uint8_t *)malloc(n);
    for (size_t i = 0; i < n; i++) d[i] = (uint8_t)('X' + (i % 3));
    CHECK(payload_roundtrip(d, n, 1, 4096, 8192) == 1);
    free(d);
}

/* ========================================================================
 * Vault engine tingkat tinggi -- bytes API
 * ======================================================================== */
TEST(test_vault_bytes_roundtrip) {
    const char *msg = "Halo dunia rahasia dari GOD Vault C edition!";
    uint8_t *blob = NULL; size_t blob_len = 0;
    gv_status_t st = gv_encrypt_bytes((const uint8_t *)msg, strlen(msg),
                                       STRONG_PW, strlen(STRONG_PW), 1, gv_kdf_preferred(),
                                       &blob, &blob_len);
    CHECK_STATUS_OK(st);
    CHECK(blob != NULL);

    uint8_t *out = NULL; size_t out_len = 0;
    st = gv_decrypt_bytes(blob, blob_len, STRONG_PW, strlen(STRONG_PW), &out, &out_len);
    CHECK_STATUS_OK(st);
    CHECK_EQ_INT(out_len, strlen(msg));
    CHECK(out && memcmp(out, msg, strlen(msg)) == 0);
    free(blob); free(out);
}

TEST(test_vault_bytes_empty_message) {
    uint8_t *blob = NULL; size_t blob_len = 0;
    gv_status_t st = gv_encrypt_bytes((const uint8_t *)"", 0, STRONG_PW, strlen(STRONG_PW),
                                       1, gv_kdf_preferred(), &blob, &blob_len);
    CHECK_STATUS_OK(st);
    uint8_t *out = NULL; size_t out_len = 999;
    st = gv_decrypt_bytes(blob, blob_len, STRONG_PW, strlen(STRONG_PW), &out, &out_len);
    CHECK_STATUS_OK(st);
    CHECK_EQ_INT(out_len, 0u);
    free(blob); free(out);
}

TEST(test_vault_bytes_wrong_password_rejected) {
    uint8_t *blob = NULL; size_t blob_len = 0;
    gv_encrypt_bytes((const uint8_t *)"rahasia", 7, STRONG_PW, strlen(STRONG_PW),
                      1, gv_kdf_preferred(), &blob, &blob_len);
    uint8_t *out = NULL; size_t out_len = 0;
    gv_status_t st = gv_decrypt_bytes(blob, blob_len, "password-salah-lain-123", 23, &out, &out_len);
    CHECK_STATUS_FAIL(st);
    CHECK(st == GV_ERR_AUTH);
    free(blob); free(out);
}

TEST(test_vault_bytes_unicode) {
    const char *msg = "Halo \xF0\x9F\x9A\x80 spesial \xC3\xB1 \xC3\xA9 \xE4\xB8\xAD\xE6\x96\x87";
    size_t msg_len = strlen(msg);
    uint8_t *blob = NULL; size_t blob_len = 0;
    gv_encrypt_bytes((const uint8_t *)msg, msg_len, STRONG_PW, strlen(STRONG_PW),
                      1, gv_kdf_preferred(), &blob, &blob_len);
    uint8_t *out = NULL; size_t out_len = 0;
    gv_status_t st = gv_decrypt_bytes(blob, blob_len, STRONG_PW, strlen(STRONG_PW), &out, &out_len);
    CHECK_STATUS_OK(st);
    CHECK_EQ_INT(out_len, msg_len);
    CHECK(out && memcmp(out, msg, msg_len) == 0);
    free(blob); free(out);
}

TEST(test_vault_bytes_multi_chunk_random) {
    size_t n = 3 * 1024 * 1024 + 777;  /* > 1 chunk default (1 MiB), sisa ganjil */
    uint8_t *data = (uint8_t *)malloc(n);
    srand(99);
    for (size_t i = 0; i < n; i++) data[i] = (uint8_t)rand();

    uint8_t *blob = NULL; size_t blob_len = 0;
    gv_status_t st = gv_encrypt_bytes(data, n, STRONG_PW, strlen(STRONG_PW),
                                       0, gv_kdf_preferred(), &blob, &blob_len);
    CHECK_STATUS_OK(st);
    uint8_t *out = NULL; size_t out_len = 0;
    st = gv_decrypt_bytes(blob, blob_len, STRONG_PW, strlen(STRONG_PW), &out, &out_len);
    CHECK_STATUS_OK(st);
    CHECK_EQ_INT(out_len, n);
    CHECK(out && memcmp(out, data, n) == 0);
    free(data); free(blob); free(out);
}

TEST(test_vault_bytes_pbkdf2_explicit) {
    uint8_t *blob = NULL; size_t blob_len = 0;
    gv_status_t st = gv_encrypt_bytes((const uint8_t *)"data pbkdf2", 11, STRONG_PW, strlen(STRONG_PW),
                                       0, GV_KDF_PBKDF2, &blob, &blob_len);
    CHECK_STATUS_OK(st);
    uint8_t *out = NULL; size_t out_len = 0;
    st = gv_decrypt_bytes(blob, blob_len, STRONG_PW, strlen(STRONG_PW), &out, &out_len);
    CHECK_STATUS_OK(st);
    CHECK(out && memcmp(out, "data pbkdf2", 11) == 0);
    free(blob); free(out);
}

/* ========================================================================
 * Deteksi tamper (harus SELALU ditolak)
 * ======================================================================== */
static uint8_t *g_tamper_blob = NULL;
static size_t g_tamper_blob_len = 0;

static void tamper_setup(void) {
    free(g_tamper_blob);
    uint8_t data[4000];
    for (int i = 0; i < 4000; i++) data[i] = (uint8_t)(i % 251);
    gv_status_t st = gv_encrypt_bytes(data, sizeof(data), STRONG_PW, strlen(STRONG_PW),
                                       0, gv_kdf_preferred(), &g_tamper_blob, &g_tamper_blob_len);
    (void)st;
}

static gv_status_t try_decrypt(const uint8_t *blob, size_t len) {
    uint8_t *out = NULL; size_t out_len = 0;
    gv_status_t st = gv_decrypt_bytes(blob, len, STRONG_PW, strlen(STRONG_PW), &out, &out_len);
    free(out);
    return st;
}

TEST(test_tamper_valid_blob_sanity) {
    tamper_setup();
    CHECK_STATUS_OK(try_decrypt(g_tamper_blob, g_tamper_blob_len));
}
TEST(test_tamper_truncation_rejected) {
    tamper_setup();
    CHECK_STATUS_FAIL(try_decrypt(g_tamper_blob, g_tamper_blob_len - 200));
}
TEST(test_tamper_bitflip_ciphertext_rejected) {
    tamper_setup();
    uint8_t *t = (uint8_t *)malloc(g_tamper_blob_len);
    memcpy(t, g_tamper_blob, g_tamper_blob_len);
    t[g_tamper_blob_len / 2] ^= 0xFF;
    CHECK_STATUS_FAIL(try_decrypt(t, g_tamper_blob_len));
    free(t);
}
TEST(test_tamper_bitflip_hmac_rejected) {
    tamper_setup();
    uint8_t *t = (uint8_t *)malloc(g_tamper_blob_len);
    memcpy(t, g_tamper_blob, g_tamper_blob_len);
    t[g_tamper_blob_len - 1] ^= 0xFF;
    CHECK_STATUS_FAIL(try_decrypt(t, g_tamper_blob_len));
    free(t);
}
TEST(test_tamper_bitflip_header_rejected) {
    tamper_setup();
    uint8_t *t = (uint8_t *)malloc(g_tamper_blob_len);
    memcpy(t, g_tamper_blob, g_tamper_blob_len);
    t[10] ^= 0xFF;  /* di area salt/parameter KDF */
    CHECK_STATUS_FAIL(try_decrypt(t, g_tamper_blob_len));
    free(t);
}
TEST(test_tamper_appended_bytes_rejected) {
    tamper_setup();
    uint8_t *t = (uint8_t *)malloc(g_tamper_blob_len + 1);
    memcpy(t, g_tamper_blob, g_tamper_blob_len);
    t[g_tamper_blob_len] = 0x42;
    CHECK_STATUS_FAIL(try_decrypt(t, g_tamper_blob_len + 1));
    free(t);
}
TEST(test_tamper_garbage_input_rejected) {
    uint8_t garbage[64];
    for (int i = 0; i < 64; i++) garbage[i] = (uint8_t)(i * 13 + 5);
    CHECK_STATUS_FAIL(try_decrypt(garbage, sizeof(garbage)));
}
TEST(test_tamper_empty_input_rejected) {
    CHECK_STATUS_FAIL(try_decrypt((const uint8_t *)"", 0));
}
TEST(test_tamper_chunk_reorder_rejected) {
    /* Data > chunk_size default (1 MiB) supaya vault-nya BENAR multi-chunk. */
    size_t n = 2500000;
    uint8_t *data = (uint8_t *)malloc(n);
    for (size_t i = 0; i < n; i++) data[i] = (uint8_t)(i % 251);
    uint8_t *blob = NULL; size_t blob_len = 0;
    gv_encrypt_bytes(data, n, STRONG_PW, strlen(STRONG_PW),
                      0, gv_kdf_preferred(), &blob, &blob_len);
    free(data);

    FILE *f = tmpfile();
    fwrite(blob, 1, blob_len, f);
    rewind(f);
    gv_header_t hdr; size_t hlen; uint8_t *hbytes;
    gv_status_t st = gv_header_read(f, &hdr, &hlen, &hbytes);
    CHECK_STATUS_OK(st);
    fclose(f);

    size_t pos = hlen, end = blob_len - GV_HMAC_DIGEST_LEN;
    /* kumpulkan offset+len tiap record chunk */
    size_t rec_off[64], rec_len[64];
    int nchunks = 0;
    while (pos < end && nchunks < 64) {
        uint32_t reclen = gv_get_u32(blob + pos);
        rec_off[nchunks] = pos;
        rec_len[nchunks] = 4 + reclen;
        pos += 4 + reclen;
        nchunks++;
    }
    CHECK(nchunks >= 2);
    if (nchunks >= 2) {
        uint8_t *tampered = (uint8_t *)malloc(blob_len);
        memcpy(tampered, blob, hlen);
        size_t w = hlen;
        /* tukar record 0 & 1, sisanya urut normal */
        memcpy(tampered + w, blob + rec_off[1], rec_len[1]); w += rec_len[1];
        memcpy(tampered + w, blob + rec_off[0], rec_len[0]); w += rec_len[0];
        for (int i = 2; i < nchunks; i++) { memcpy(tampered + w, blob + rec_off[i], rec_len[i]); w += rec_len[i]; }
        memcpy(tampered + w, blob + end, GV_HMAC_DIGEST_LEN); w += GV_HMAC_DIGEST_LEN;
        CHECK_EQ_INT(w, blob_len);

        CHECK_STATUS_FAIL(try_decrypt(tampered, blob_len));
        free(tampered);
    }
    free(hbytes);
    free(blob);
}

/* ========================================================================
 * File API (streaming)
 * ======================================================================== */
TEST(test_file_roundtrip_no_compress) {
    char in_path[512], out_path[512], dec_path[512];
    gv_test_tmp_path(in_path, sizeof(in_path), "gvtest_in_XXXXXX");
    gv_test_tmp_path(out_path, sizeof(out_path), "gvtest_out_XXXXXX");
    gv_test_tmp_path(dec_path, sizeof(dec_path), "gvtest_dec_XXXXXX");
    int fd1 = mkstemp(in_path); int fd2 = mkstemp(out_path); int fd3 = mkstemp(dec_path);
    CHECK(fd1 >= 0 && fd2 >= 0 && fd3 >= 0);
    if (fd1 < 0 || fd2 < 0 || fd3 < 0) {
        if (fd1 >= 0) close(fd1);
        if (fd2 >= 0) close(fd2);
        if (fd3 >= 0) close(fd3);
        return;  /* jangan lanjut ke fdopen/fwrite dgn fd tidak valid */
    }
    close(fd2); close(fd3);

    size_t n = 800000;
    uint8_t *data = (uint8_t *)malloc(n);
    srand(123);
    for (size_t i = 0; i < n; i++) data[i] = (uint8_t)rand();
    FILE *f = fdopen(fd1, "wb");
    CHECK(f != NULL);
    if (!f) { free(data); return; }
    fwrite(data, 1, n, f);
    fclose(f);

    gv_status_t st = gv_encrypt_file(in_path, out_path, STRONG_PW, strlen(STRONG_PW),
                                      0, gv_kdf_preferred(), 65536, NULL, NULL);
    CHECK_STATUS_OK(st);

    gv_header_t meta;
    st = gv_decrypt_file(out_path, dec_path, STRONG_PW, strlen(STRONG_PW), &meta, NULL, NULL);
    CHECK_STATUS_OK(st);
    CHECK(meta.source_size == n);

    FILE *fr = fopen(dec_path, "rb");
    CHECK(fr != NULL);
    if (fr) {
        uint8_t *result = (uint8_t *)malloc(n);
        size_t got = fread(result, 1, n, fr);
        fclose(fr);
        CHECK_EQ_INT(got, n);
        CHECK(memcmp(result, data, n) == 0);
        free(result);
    }

    remove(in_path); remove(out_path); remove(dec_path);
    free(data);
}

TEST(test_file_roundtrip_compressed) {
    char in_path[512], out_path[512], dec_path[512];
    gv_test_tmp_path(in_path, sizeof(in_path), "gvtest_in2_XXXXXX");
    gv_test_tmp_path(out_path, sizeof(out_path), "gvtest_out2_XXXXXX");
    gv_test_tmp_path(dec_path, sizeof(dec_path), "gvtest_dec2_XXXXXX");
    int fd1 = mkstemp(in_path); int fd2 = mkstemp(out_path); int fd3 = mkstemp(dec_path);
    CHECK(fd1 >= 0 && fd2 >= 0 && fd3 >= 0);
    if (fd1 < 0 || fd2 < 0 || fd3 < 0) {
        if (fd1 >= 0) close(fd1);
        if (fd2 >= 0) close(fd2);
        if (fd3 >= 0) close(fd3);
        return;
    }
    close(fd2); close(fd3);

    const char *chunk = "Halo dunia! ";
    size_t chunk_len = strlen(chunk);
    FILE *f = fdopen(fd1, "wb");
    CHECK(f != NULL);
    if (!f) return;
    for (int i = 0; i < 20000; i++) fwrite(chunk, 1, chunk_len, f);
    fclose(f);
    long total_len = 20000L * (long)chunk_len;

    gv_status_t st = gv_encrypt_file(in_path, out_path, STRONG_PW, strlen(STRONG_PW),
                                      1, gv_kdf_preferred(), GV_DEFAULT_CHUNK_SIZE, NULL, NULL);
    CHECK_STATUS_OK(st);

    st = gv_decrypt_file(out_path, dec_path, STRONG_PW, strlen(STRONG_PW), NULL, NULL, NULL);
    CHECK_STATUS_OK(st);

    FILE *fin = fopen(in_path, "rb"); FILE *fout = fopen(dec_path, "rb");
    CHECK(fin != NULL && fout != NULL);
    if (fin && fout) {
        int same = 1;
        int a, b;
        long compared = 0;
        while ((a = fgetc(fin)) != EOF) {
            b = fgetc(fout);
            if (a != b) { same = 0; break; }
            compared++;
        }
        if (fgetc(fout) != EOF) same = 0;
        CHECK(same);
        CHECK_EQ_INT(compared, total_len);
    }
    if (fin) fclose(fin);
    if (fout) fclose(fout);

    remove(in_path); remove(dec_path);
    /* cek kompresi benar2 mengecilkan ukuran */
    FILE *fv = fopen(out_path, "rb");
    CHECK(fv != NULL);
    if (fv) {
        fseek(fv, 0, SEEK_END);
        long vault_size = ftell(fv);
        fclose(fv);
        CHECK(vault_size < total_len);
    }
    remove(out_path);
}

TEST(test_file_wrong_password_removes_partial_output) {
    char in_path[512], out_path[512], dec_path[512];
    gv_test_tmp_path(in_path, sizeof(in_path), "gvtest_in3_XXXXXX");
    gv_test_tmp_path(out_path, sizeof(out_path), "gvtest_out3_XXXXXX");
    gv_test_tmp_path(dec_path, sizeof(dec_path), "gvtest_dec3_XXXXXX");
    int fd1 = mkstemp(in_path); int fd2 = mkstemp(out_path);
    CHECK(fd1 >= 0 && fd2 >= 0);
    if (fd1 < 0 || fd2 < 0) {
        if (fd1 >= 0) close(fd1);
        if (fd2 >= 0) close(fd2);
        return;
    }
    close(fd2);
    FILE *f = fdopen(fd1, "wb");
    CHECK(f != NULL);
    if (!f) return;
    fputs("data rahasia", f);
    fclose(f);

    gv_encrypt_file(in_path, out_path, STRONG_PW, strlen(STRONG_PW), 0, gv_kdf_preferred(),
                     GV_DEFAULT_CHUNK_SIZE, NULL, NULL);

    remove(dec_path);  /* pastikan belum ada */
    gv_status_t st = gv_decrypt_file(out_path, dec_path, "password-salah-total", 20, NULL, NULL, NULL);
    CHECK_STATUS_FAIL(st);

    FILE *check = fopen(dec_path, "rb");
    CHECK(check == NULL);  /* file output TIDAK boleh ada setelah gagal */
    if (check) fclose(check);

    remove(in_path); remove(out_path); remove(dec_path);
}

/* ========================================================================
 * Rate limiter
 * ======================================================================== */
TEST(test_ratelimiter_allows_initially) {
    char path[512];
    gv_test_tmp_path(path, sizeof(path), "gvtest_rl_XXXXXX");
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0) return;
    close(fd); remove(path);
    gv_ratelimiter_t rl; gv_ratelimiter_init(&rl, path);
    int64_t wait;
    CHECK(gv_ratelimiter_check(&rl, &wait) == true);
    remove(path);
}
TEST(test_ratelimiter_cooldown_after_max_attempts) {
    char path[512];
    gv_test_tmp_path(path, sizeof(path), "gvtest_rl2_XXXXXX");
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0) return;
    close(fd); remove(path);
    gv_ratelimiter_t rl; gv_ratelimiter_init(&rl, path);
    for (int i = 0; i < GV_RATELIMIT_MAX_ATTEMPTS; i++) gv_ratelimiter_record(&rl, false);
    int64_t wait = -1;
    CHECK(gv_ratelimiter_check(&rl, &wait) == false);
    CHECK(wait > 0);
    remove(path);
}
TEST(test_ratelimiter_success_resets) {
    char path[512];
    gv_test_tmp_path(path, sizeof(path), "gvtest_rl3_XXXXXX");
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0) return;
    close(fd); remove(path);
    gv_ratelimiter_t rl; gv_ratelimiter_init(&rl, path);
    for (int i = 0; i < GV_RATELIMIT_MAX_ATTEMPTS; i++) gv_ratelimiter_record(&rl, false);
    gv_ratelimiter_record(&rl, true);
    int64_t wait;
    CHECK(gv_ratelimiter_check(&rl, &wait) == true);
    remove(path);
}

/* ========================================================================
 * main
 * ======================================================================== */
int main(void) {
    printf("=== CRYPTO//GOD VAULT (C edition) -- unit test suite ===\n");
    printf("Argon2id tersedia: %s\n\n", gv_argon2_available() ? "YA" : "TIDAK (fallback PBKDF2 saja)");

    printf("-- Password validator --\n");
    RUN(test_password_too_short);
    RUN(test_password_missing_classes);
    RUN(test_password_strong_accepted);
    RUN(test_password_entropy_zero_for_empty);
    RUN(test_password_generate_length_and_charset);
    RUN(test_password_generate_distinct);

    printf("-- Base64 --\n");
    RUN(test_base64_roundtrip_various_lengths);
    RUN(test_base64_rejects_malformed);

    printf("-- KDF (cross-validated thd referensi Python) --\n");
    RUN(test_hkdf_matches_reference_vector);
    RUN(test_pbkdf2_matches_reference_vector);
#ifdef GV_WITH_ARGON2
    RUN(test_argon2id_matches_reference_vector);
#endif

    printf("-- AES-256-GCM primitif --\n");
    RUN(test_aes_gcm_roundtrip_and_tamper);

    printf("-- Payload iterator (chunking + kompresi streaming) --\n");
    RUN(test_payload_iter_empty);
    RUN(test_payload_iter_exact_chunk_boundary);
    RUN(test_payload_iter_multi_chunk);
    RUN(test_payload_iter_multi_chunk_compressed);

    printf("-- Vault bytes API --\n");
    RUN(test_vault_bytes_roundtrip);
    RUN(test_vault_bytes_empty_message);
    RUN(test_vault_bytes_wrong_password_rejected);
    RUN(test_vault_bytes_unicode);
    RUN(test_vault_bytes_multi_chunk_random);
    RUN(test_vault_bytes_pbkdf2_explicit);

    printf("-- Deteksi tamper (semua HARUS ditolak) --\n");
    RUN(test_tamper_valid_blob_sanity);
    RUN(test_tamper_truncation_rejected);
    RUN(test_tamper_bitflip_ciphertext_rejected);
    RUN(test_tamper_bitflip_hmac_rejected);
    RUN(test_tamper_bitflip_header_rejected);
    RUN(test_tamper_appended_bytes_rejected);
    RUN(test_tamper_garbage_input_rejected);
    RUN(test_tamper_empty_input_rejected);
    RUN(test_tamper_chunk_reorder_rejected);
    free(g_tamper_blob);

    printf("-- File API (streaming) --\n");
    RUN(test_file_roundtrip_no_compress);
    RUN(test_file_roundtrip_compressed);
    RUN(test_file_wrong_password_removes_partial_output);

    printf("-- Rate limiter --\n");
    RUN(test_ratelimiter_allows_initially);
    RUN(test_ratelimiter_cooldown_after_max_attempts);
    RUN(test_ratelimiter_success_resets);

    printf("\n=== HASIL: %d OK, %d GAGAL (dari %d assertion) ===\n",
           g_pass, g_fail, g_pass + g_fail);
    return g_fail == 0 ? 0 : 1;
}
