/* ==========================================================================
 * vault_format.h — CRYPTO//GOD VAULT (C EDITION) v1.0
 * ==========================================================================
 * Format vault BINER MURNI, sengaja BUKAN JSON.
 *
 * Kenapa: versi Python menyimpan parameter KDF & metadata sebagai blob JSON
 * di dalam header. Itu nyaman di Python (json.loads bawaan, aman dari
 * overflow karena Python memory-safe). Di C, mem-parsing JSON dari data yang
 * BELUM TEPERCAYA (header vault bisa saja dimanipulasi penyerang) adalah
 * permukaan serangan ekstra yang tidak perlu -- setiap parser teks
 * menambah risiko out-of-bounds read/write kalau tidak diaudit ketat.
 *
 * Solusinya: header di sini 100% FIELD BINER UKURAN TETAP (kecuali nama
 * file, yang punya panjang eksplisit & dibatasi MAX_FILENAME_LEN). Tidak
 * ada text parsing sama sekali untuk data yang belum diverifikasi.
 *
 * Konsekuensinya: vault C (magic "GODC") TIDAK bisa saling-baca dengan
 * vault Python (magic "GOD2"/.vault). Ini keputusan desain yang disengaja,
 * bukan keterbatasan yang tidak disadari -- arsitektur keamanannya (KDF
 * Argon2id/PBKDF2 -> HKDF pisah kunci -> AES-256-GCM per-chunk dgn nonce
 * counter -> HMAC-SHA512 ganda, verifikasi 2-pass) tetap identik filosofinya
 * dengan versi Python.
 * ========================================================================== */
#ifndef GODVAULT_FORMAT_H
#define GODVAULT_FORMAT_H

#include <stdint.h>
#include <stddef.h>

#define GV_MAGIC        "GODC"      /* 4 byte, TANPA null terminator saat ditulis */
#define GV_MAGIC_LEN    4
#define GV_VERSION      1

#define GV_KDF_ARGON2ID 1
#define GV_KDF_PBKDF2   2

#define GV_SALT_LEN         32
#define GV_NONCE_PREFIX_LEN 4
#define GV_NONCE_COUNTER_LEN 8
#define GV_NONCE_LEN        (GV_NONCE_PREFIX_LEN + GV_NONCE_COUNTER_LEN)  /* 12 byte / 96-bit */
#define GV_KEY_LEN          32      /* AES-256 */
#define GV_GCM_TAG_LEN      16
#define GV_HMAC_KEY_LEN     32
#define GV_HMAC_DIGEST_LEN  64      /* SHA-512 */

#define GV_MAX_FILENAME_LEN 4096    /* batas keras nama file di header */

#define GV_DEFAULT_CHUNK_SIZE      (1024 * 1024)   /* 1 MiB plaintext per chunk AEAD */
#define GV_DECOMPRESS_MAX_OUTPUT   (1024 * 1024)   /* batas output per panggilan inflate() */
#define GV_READ_BLOCK_SIZE         (1024 * 1024)

/* Parameter Argon2id default -- OWASP opsi ke-2 (m=64MiB, t=3, p=4),
 * sama dengan default versi Python. */
#define GV_ARGON2_MEMORY_KIB   65536
#define GV_ARGON2_TIME_COST    3
#define GV_ARGON2_PARALLELISM  4
#define GV_ARGON2_HASH_LEN     32

/* PBKDF2-HMAC-SHA512 fallback -- OWASP 2023 (>= 1 juta iterasi). */
#define GV_PBKDF2_ITERATIONS   1000000

#define GV_MIN_PASSWORD_LEN    12
#define GV_MIN_ENTROPY_BITS    50.0

#define GV_RATE_LIMIT_MAX_ATTEMPTS   5
#define GV_RATE_LIMIT_COOLDOWN_BASE  30   /* detik */

/* --------------------------------------------------------------------------
 * Header vault (semua field big-endian / network order saat ditulis ke
 * disk -- struct ini adalah representasi IN-MEMORY sesudah di-parse,
 * bukan layout on-disk literal, supaya bebas masalah padding/alignment
 * antar compiler & arsitektur).
 * ------------------------------------------------------------------------ */
typedef struct {
    uint8_t  version;
    uint8_t  kdf_id;
    uint8_t  compressed;         /* 0/1 */
    uint32_t kdf_mem_cost;       /* Argon2: KiB memori. PBKDF2: 0 (tidak dipakai) */
    uint32_t kdf_time_cost;      /* Argon2: time_cost. PBKDF2: iterasi */
    uint8_t  kdf_parallelism;    /* Argon2: parallelism. PBKDF2: 0 */
    uint8_t  salt[GV_SALT_LEN];
    uint8_t  nonce_prefix[GV_NONCE_PREFIX_LEN];
    char     filename[GV_MAX_FILENAME_LEN + 1];  /* +1 utk null terminator lokal */
    uint16_t filename_len;
    uint64_t source_size;
    int64_t  timestamp;          /* unix epoch detik saat enkripsi */
} gv_header_t;

/* Kode error terpadu -- SEMUA kegagalan verifikasi (password salah, data
 * dimanipulasi, header korup) sengaja memetakan ke pesan yang sama di
 * lapisan atas, supaya tidak jadi oracle. Kode di bawah untuk kebutuhan
 * internal/logging, bukan untuk ditampilkan berbeda-beda ke pengguna akhir. */
typedef enum {
    GV_OK = 0,
    GV_ERR_IO,
    GV_ERR_FORMAT,          /* header/format tidak valid / bukan vault GODC */
    GV_ERR_UNSUPPORTED,     /* versi/KDF tidak didukung build ini */
    GV_ERR_AUTH,            /* password salah ATAU data dimanipulasi/korup */
    GV_ERR_POLICY,          /* password tidak memenuhi kebijakan */
    GV_ERR_RATE_LIMIT,
    GV_ERR_MEMORY,
    GV_ERR_CRYPTO,          /* kegagalan internal library kripto */
} gv_status_t;

const char *gv_status_str(gv_status_t s);

#endif /* GODVAULT_FORMAT_H */
