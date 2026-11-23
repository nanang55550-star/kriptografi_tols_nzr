# CRYPTO//GOD VAULT — C Edition

Port C dari `crypto_god_vault.py` (v3.0), dibangun di atas pustaka kriptografi
teraudit — **bukan** implementasi AES/Argon2/HMAC buatan sendiri:

| Fungsi                     | Pustaka                         |
|-----------------------------|----------------------------------|
| AES-256-GCM                 | OpenSSL (EVP)                   |
| HMAC-SHA512                 | OpenSSL (EVP_MAC)                |
| PBKDF2-HMAC-SHA512           | OpenSSL                         |
| Argon2id                     | libargon2 (opsional; paket: `libargon2-dev` di Debian/Ubuntu, `argon2` di Termux/brew — fallback ke PBKDF2 kalau tidak ada) |
| Kompresi streaming            | zlib                            |
| HKDF-SHA512                  | dibangun dari HMAC-SHA512 OpenSSL (konstruksi RFC 5869 standar, divalidasi silang thd `cryptography` Python — lihat `tests/test_vault.c`) |
| Base64                       | implementasi sendiri (encoding biasa, bukan primitif kripto) |

## ⚠️ Perbedaan format dari versi Python — DISENGAJA

Vault C (magic `GODC`) **tidak** bisa saling-baca dengan vault Python (magic
`GOD2`, `.vault`). Ini keputusan keamanan yang disengaja:

Python menyimpan parameter KDF & metadata sebagai JSON di header. Di Python
itu aman (parser JSON bawaan, memory-safe). Di C, mem-parsing teks/JSON dari
data yang **belum tepercaya** (header vault bisa dimanipulasi penyerang)
adalah permukaan serangan tambahan yang tidak perlu. Solusinya: header C
100% field biner ukuran tetap, tanpa text parsing sama sekali untuk data
yang belum diverifikasi.

Arsitektur keamanannya **identik filosofinya** dengan versi Python:
- KDF Argon2id (prioritas) / PBKDF2-HMAC-SHA512 (fallback), parameter
  disimpan di header (bukan konstanta hardcoded) — vault lama tetap valid
  walau default berubah di versi mendatang.
- HKDF-SHA512 memisahkan kunci enkripsi dari kunci HMAC (kompromi satu
  tidak otomatis membocorkan yang lain).
- AES-256-GCM per-chunk dengan **nonce counter-based**: prefix acak 32-bit
  (sekali per vault) + counter 64-bit (naik tiap chunk) — keunikan
  terjamin *deterministik*, bukan cuma probabilistik seperti nonce acak
  murni per-chunk.
- HMAC-SHA512 lapis kedua di atas seluruh header+ciphertext stream,
  **diverifikasi lebih dulu (constant-time compare)** sebelum satu chunk
  pun didekripsi — plaintext yang belum terautentikasi tidak pernah
  sempat ditulis ke disk.
- Kompresi & dekompresi streaming (zlib), memori nyaris konstan berapa
  pun ukuran file — termasuk pembatasan output per panggilan `inflate()`
  supaya rasio kompresi ekstrem tidak memicu lonjakan memori.

## Keunggulan nyata dibanding versi Python

- **Penghapusan memori password terjamin**: `OPENSSL_cleanse()` tidak bisa
  dioptimasi-hilang oleh compiler (beda dengan `memset()` biasa yang boleh
  "dihapus" compiler kalau memori itu tak dibaca lagi — lubang keamanan
  klasik). Python cuma bisa best-effort lewat overwrite bytearray.
- **Constant-time compare** via `CRYPTO_memcmp()` (OpenSSL) untuk semua
  perbandingan HMAC/tag.
- Tanpa runtime/GC — jejak memori & startup lebih kecil, cocok untuk
  perangkat terbatas (Termux/Android).

## Build

Dependensi wajib: OpenSSL, zlib. Opsional (sangat disarankan): libargon2.

```bash
# Debian/Ubuntu
sudo apt install build-essential libssl-dev libargon2-dev zlib1g-dev

# Termux (Android)
pkg install clang openssl argon2 zlib pkg-config make

# macOS (Homebrew)
brew install openssl@3 argon2 zlib pkg-config
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig:$(brew --prefix argon2)/lib/pkgconfig:$(brew --prefix zlib)/lib/pkgconfig"
```

```bash
make          # -> bin/godvaultc
make test     # build & jalankan seluruh unit test (tests/test_vault.c)
make clean
```

Kalau libargon2 tidak terdeteksi, build tetap jalan (warning ditampilkan)
dengan fallback PBKDF2-HMAC-SHA512 1 juta iterasi saja.

## Pemakaian

```bash
./bin/godvaultc                 # menu interaktif
./bin/godvaultc enc -m "teks"
./bin/godvaultc enc -i file -o file.gvc [--no-compress] [--force] [--kdf argon2id|pbkdf2]
./bin/godvaultc dec -m "teks-base64"
./bin/godvaultc dec -i file.gvc -o file.out
./bin/godvaultc genpass -l 24
./bin/godvaultc status
```

Konvensi Unix: pesan status/prompt/progress → **stderr**; hasil (ciphertext
base64, plaintext, password acak) → **stdout** murni, aman di-pipe/redirect.

## Verifikasi yang sudah dilakukan

- **602 assertion** di `tests/test_vault.c`, mencakup: KDF (cross-validated
  bit-exact terhadap `cryptography`/`argon2-cffi` Python via reference
  vector ter-hardcode), AES-256-GCM, dekompresi streaming, roundtrip
  teks/file, multi-chunk + keunikan nonce, 9 skenario tamper (bit-flip,
  truncation, append, **reorder chunk**, garbage, kosong), password
  validator/generator, rate limiter.
- **Valgrind** (`--leak-check=full --track-origins=yes`): 0 error, 0 leak,
  di seluruh test suite maupun jalur CLI (termasuk jalur kegagalan:
  password salah, file tamper).
- Uji memori file 150MB rasio kompresi ~300:1 → peak RSS ~71MB (bounded,
  tidak proporsional ukuran file).

## Catatan dari pengujian di perangkat Android/Termux nyata

Setelah diuji langsung di Termux (Android ARM64), dua perbaikan masuk:

1. **Nama paket Termux yang benar** adalah `argon2` (bukan `libargon2` seperti
   distro Debian/Ubuntu) — sudah diperbaiki di instruksi build di atas.
2. **Bug di test suite** (bukan di library-nya): helper `write_temp_file()`
   di `tests/test_vault.c` berasumsi `/tmp` selalu ada & bisa ditulis. Di
   Android, `/tmp` sering **tidak ada sama sekali** di sandbox aplikasi
   (beda dengan Linux desktop), dan kalau `$TMPDIR` juga tidak ter-set di
   shell yang menjalankan `make test`, `mkstemp()` gagal — yang berujung
   `FILE*` NULL dipakai tanpa terguard dgn benar di satu titik, kena
   `FORTIFY_SOURCE` Bionic libc dan proses di-abort. Sudah diperbaiki:
   fallback direktori temp sekarang `.` (direktori kerja saat `make test`
   dijalankan, hampir selalu bisa ditulis) alih-alih asumsi `/tmp` ada.
   **Ini murni bug di test harness, bukan di `vault_api.c`** — API level
   file (`gv_encrypt_file`/`gv_decrypt_file`) selalu memakai path yang
   diberikan pemanggil (CLI/menu), tidak pernah mengasumsikan direktori
   temp sistem.

Hasil benchmark 1 GiB di ARM64 mobile: verifikasi HMAC ~146 MiB/s dan
dekripsi AES-256-GCM ~190 MiB/s (kemungkinan besar terbantu akselerasi
ARMv8 Crypto Extensions kalau chipset mendukung). Enkripsi dgn kompresi
aktif jauh lebih lambat (~13.5 MiB/s) kalau file sumbernya SUDAH
terkompresi (mis. `.zip`) — itu memang biaya sia-sia mencoba
mengompres ulang data yang sudah padat, bukan overhead algoritma
enkripsinya. Pakai `--no-compress` untuk file yang sudah dalam format
terkompresi (zip, jpg, mp4, dst).

## Struktur


```
src/
  vault_format.h    konstanta & struct header (biner, bukan JSON)
  util.*            wipe memori, big-endian pack/unpack, growable buffer
  kdf.*             Argon2id / PBKDF2 + HKDF key separation
  crypto_core.*      AES-256-GCM per-chunk, HMAC-SHA512 streaming, nonce/AAD
  compress.*         deflate/inflate streaming (bounded memory)
  payload_iter.*      penyatuan baca-file + kompresi opsional -> chunk siap-enkripsi
  header_codec.*      pack/parse header (baca byte mentah persis, bukan rekonstruksi)
  vault_api.*         API tingkat tinggi: encrypt/decrypt stream/file/bytes
  base64.*            base64 standar (utk mode teks CLI)
  password.*          validator entropi + generator (rejection sampling, CSPRNG)
  ratelimit.*          anti brute-force, cooldown eksponensial
  progress.*           progress bar terminal (stderr, auto nonaktif kalau bukan TTY)
  term.*                baca password tanpa echo (termios), banner, pesan berwarna
  main.c                CLI + menu interaktif
tests/test_vault.c      unit test (framework assert minimal, tanpa dependensi eksternal)
Makefile
```
