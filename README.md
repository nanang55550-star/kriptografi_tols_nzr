# CRYPTO//GOD VAULT — Cryptography Tools

Tool kriptografi canggih dengan standar keamanan *god-tier*, tersedia dalam dua implementasi:
1. **Python Edition** (di direktori root `main.py`)
2. **C Edition** (di subdirektoril [`c_version/`](c_version/))

---

## Fitur Utama

- **KDF**: Argon2id (prioritas) / PBKDF2-HMAC-SHA512 (fallback).
- **Cipher**: AES-256-GCM AEAD per-chunk dengan nonce deterministik (counter-based).
- **Key Separation**: HKDF-SHA512 (memisahkan kunci enkripsi AES dan kunci autentikasi HMAC).
- **Dual-Layer Authentication**: HMAC-SHA512 memverifikasi integritas file sebelum dekripsi chunk.
- **Kompresi Streaming**: Zlib hemat memori untuk file berukuran besar.

---

## 1. Menjalankan Versi Python

### Instalasi Dependensi:
```bash
pip install -r requirements.txt
```

### Menjalankan:
```bash
python3 main.py
```

---

## 2. Menjalankan Versi C (`c_version`)

Masuk ke folder `c_version`:
```bash
cd c_version
```

### Instalasi Dependensi:
- **Debian / Ubuntu:**
  ```bash
  sudo apt update && sudo apt install build-essential libssl-dev libargon2-dev zlib1g-dev pkg-config
  ```
- **Termux (Android):**
  ```bash
  pkg install clang openssl argon2 zlib pkg-config make
  ```
- **Alpine Linux:**
  ```bash
  apk add build-base openssl-dev argon2-dev zlib-dev pkgconf
  ```
- **macOS:**
  ```bash
  brew install openssl@3 argon2 zlib pkg-config
  ```

### Kompilasi & Menjalankan:
```bash
make            # Kompilasi ke bin/godvaultc
make test       # Jalankan unit test

./bin/godvaultc # Jalankan menu interaktif
```

Detail teknis arsitektur C dapat dilihat di [c_version/README.md](c_version/README.md).
