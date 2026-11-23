#!/usr/bin/env python3
"""
CRYPTO//GOD VAULT — v3.0 "MERGED GOD-TIER"
===========================================
Menggabungkan dua garis keturunan:
  - GOD-TIER CRYPTOGRAPHIC VAULT v1.0  -> keamanan berlapis (Argon2id, HKDF
    key-separation, dual-layer HMAC-SHA512, password policy, rate limiter)
  - CRYPTO//GOD v2.0                   -> kesederhanaan pemakaian (CLI
    argparse, menu interaktif, generator password)

Yang BARU di v3.0 (permintaan upgrade ini):
  §A  CLI mode bergaya CRYPTO//GOD (enc/dec/genpass/status, argparse penuh)
  §B  Nonce di-fix jadi COUNTER-BASED, bukan murni acak per-chunk:
        nonce (96-bit) = prefix acak (32-bit, sekali per operasi enkripsi)
                        + counter (64-bit, naik 1 tiap chunk: 0,1,2,...)
      Kenapa ini "lebih benar" dibanding nonce acak per-chunk: begitu satu
      kunci dipakai untuk banyak chunk (file besar), nonce ACAK 96-bit
      punya risiko birthday-bound collision setelah ~2^32-2^48 chunk.
      Nonce counter menjamin KEUNIKAN SECARA DETERMINISTIK (bukan cuma
      probabilistik) selama counter tidak pernah diulang -- yang mustahil
      untuk ukuran file berapa pun yang realistis (counter 64-bit).
  §C  StreamVault: enkripsi/dekripsi file dalam chunk (bukan baca seluruh
      file ke memori) -> hemat RAM untuk file besar, terutama penting di
      perangkat mobile/Termux dengan RAM terbatas.
  §D  Unit test suite lengkap (file terpisah: test_crypto_god_vault.py)
  §E  Fix bug keamanan: SecureBuffer versi lama memakai ctypes.memset() di
      alamat memori hasil id()+offset tebakan -- ini TIDAK AMAN (offset
      header objek Python bisa beda-beda antar versi/build & untuk
      bytearray datanya malah tidak inline setelah header, jadi trik itu
      menimpa lokasi memori yang salah dan berisiko crash/corruption).
      Diganti dengan overwrite murni Python yang benar-benar menyentuh
      buffer bytearray-nya.

Algoritma:
  KDF     : Argon2id (prioritas) atau PBKDF2-HMAC-SHA512 1,000,000 iterasi
  Cipher  : AES-256-GCM per chunk, AEAD
  KeySep  : HKDF-SHA512 (kunci enkripsi & kunci HMAC dipisah dari master key)
  MAC     : HMAC-SHA512 lapis kedua di atas seluruh header+ciphertext stream
  Nonce   : counter-based (prefix 32-bit acak + counter 64-bit big-endian)
  Format  : Binary vault ber-versi, metadata & parameter KDF terautentikasi

Instalasi dependensi opsional (SANGAT DISARANKAN untuk KDF terbaik):
    pip install argon2-cffi
"""
from __future__ import annotations

import os
import io
import sys
import base64
import json
import zlib
import hmac
import hashlib
import getpass
import time
import struct
import secrets
import string
import argparse
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, BinaryIO, Callable
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

try:
    from argon2.low_level import hash_secret_raw, Type as _Argon2Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════
# §1  KONSTANTA & FORMAT VAULT
# ══════════════════════════════════════════════════════════════════════════

MAGIC   = b"GOD2"      # v2 format (chunked/streaming) -- TIDAK kompatibel
VERSION = 2            # dengan vault GOD1 (v1, single-shot) atau CRG1.

KDF_ARGON2ID = 1
KDF_PBKDF2   = 2

ARGON2_MEMORY_COST = 65536      # 64 MiB  (OWASP: opsi Argon2id ke-2)
ARGON2_TIME_COST   = 3
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN    = 32

PBKDF2_ITERATIONS = 1_000_000    # OWASP 2023, PBKDF2-HMAC-SHA512
PBKDF2_HASH       = hashes.SHA512()

SALT_LEN        = 32
AES_KEY_SIZE     = 32            # AES-256
NONCE_PREFIX_LEN = 4             # bagian acak dari nonce (sekali per vault)
NONCE_COUNTER_LEN = 8            # bagian counter dari nonce (per chunk)
NONCE_LEN        = NONCE_PREFIX_LEN + NONCE_COUNTER_LEN   # 12 byte (96-bit)
GCM_TAG_LEN      = 16

HMAC_KEY_SIZE     = 32
HMAC_HASH         = hashlib.sha512
HMAC_DIGEST_SIZE  = 64

DEFAULT_CHUNK_SIZE = 1024 * 1024   # 1 MiB plaintext per chunk
DECOMPRESS_MAX_OUTPUT = 1024 * 1024  # batas output per panggilan decompress()

MAX_ATTEMPTS  = 5
COOLDOWN_BASE = 30       # detik
DEFAULT_RATE_LIMIT_FILE = Path.home() / ".godcrypto_rate_limit.json"

MIN_PASSWORD_LENGTH = 12
MIN_ENTROPY_BITS    = 50


class VaultError(Exception):
    """Semua kegagalan terkait vault (password salah, data korup, format
    tidak dikenal, dll) muncul sebagai exception ini -- sengaja TIDAK
    dibedakan pesannya per penyebab, supaya tidak jadi oracle bagi
    penyerang yang mencoba menebak password."""
    pass


# ══════════════════════════════════════════════════════════════════════════
# §2  TEMA TERMINAL (CYBERPUNK)
# ══════════════════════════════════════════════════════════════════════════

class C:
    _ON = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET   = "\033[0m" if _ON else ""
    BOLD    = "\033[1m" if _ON else ""
    DIM     = "\033[2m" if _ON else ""
    CYAN    = "\033[38;5;51m"  if _ON else ""
    MAGENTA = "\033[38;5;201m" if _ON else ""
    GREEN   = "\033[38;5;46m"  if _ON else ""
    YELLOW  = "\033[38;5;226m" if _ON else ""
    RED     = "\033[38;5;196m" if _ON else ""
    GREY    = "\033[38;5;244m" if _ON else ""


def banner() -> None:
    print(f"{C.MAGENTA}{C.BOLD}")
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║   C R Y P T O / / G O D   V A U L T   —  v3.0 MERGED       ║")
    print("║   AES-256-GCM · Argon2id/PBKDF2 · HKDF · HMAC-SHA512 ×2     ║")
    print("║   Counter-nonce · Streaming chunk · Rate-limit              ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print(C.RESET, end="")


def info(msg: str)  -> None: print(f"{C.CYAN}[INFO]{C.RESET} {msg}")
def ok(msg: str)    -> None: print(f"{C.GREEN}[ OK ]{C.RESET} {msg}")
def warn(msg: str)  -> None: print(f"{C.YELLOW}[WARN]{C.RESET} {msg}")
def error(msg: str) -> None: print(f"{C.RED}[FAIL]{C.RESET} {msg}")


# ══════════════════════════════════════════════════════════════════════════
# §3  SECURE MEMORY (diperbaiki dari versi lama)
# ══════════════════════════════════════════════════════════════════════════

class SecureBuffer:
    """Buffer sensitif dengan overwrite memori best-effort.

    CATATAN JUJUR soal keterbatasan: CPython tidak menjamin ini menghapus
    SEMUA salinan password dari RAM (mis. hasil encode() sebelumnya, atau
    salinan yang sempat dibuat GC, tetap bisa ada di tempat lain). Versi
    SEBELUMNYA mencoba "akali" ini dengan ctypes.memset(id(buf)+32, ...)
    -- itu BUG, bukan fitur: offset 32 itu tebakan terhadap layout header
    objek CPython yang tidak dijamin stabil, dan untuk bytearray data
    aktualnya belum tentu ada tepat di alamat itu. Kalau tebakannya
    meleset, ini bisa menimpa memori yang salah (memory corruption,
    berpotensi crash). Makanya di versi ini dihapus total; kita hanya
    menimpa isi bytearray lewat API Python biasa, yang aman dan memang
    benar-benar menyentuh buffer yang kita pegang.
    """

    def __init__(self, data: bytes):
        self._data = bytearray(data)
        self._wiped = False

    @property
    def data(self) -> bytes:
        if self._wiped:
            raise RuntimeError("Buffer sudah di-wipe")
        return bytes(self._data)

    def wipe(self) -> None:
        if not self._wiped:
            for i in range(len(self._data)):
                self._data[i] = 0
            self._wiped = True

    def __del__(self):
        self.wipe()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()
        return False


def _wipe_bytes(*buffers: bytearray) -> None:
    for buf in buffers:
        for i in range(len(buf)):
            buf[i] = 0


# ══════════════════════════════════════════════════════════════════════════
# §4  VALIDATOR KEKUATAN PASSWORD
# ══════════════════════════════════════════════════════════════════════════

class PasswordValidator:
    @staticmethod
    def calculate_entropy(password: str) -> float:
        if not password:
            return 0.0
        charset_size = 0
        if any(c.islower() for c in password): charset_size += 26
        if any(c.isupper() for c in password): charset_size += 26
        if any(c.isdigit() for c in password): charset_size += 10
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password): charset_size += 32
        if any(ord(c) > 127 for c in password): charset_size += 50

        if charset_size == 0:
            return 0.0

        import math
        entropy = len(password) * math.log2(charset_size)

        unique_ratio = len(set(password)) / len(password)
        entropy *= unique_ratio

        sequential_penalty = 0
        for i in range(len(password) - 2):
            if ord(password[i + 1]) - ord(password[i]) == ord(password[i + 2]) - ord(password[i + 1]):
                sequential_penalty += 1
        entropy *= max(0.3, 1 - (sequential_penalty / len(password)))

        return entropy

    @classmethod
    def validate(cls, password: str) -> Tuple[bool, str]:
        if len(password) < MIN_PASSWORD_LENGTH:
            return False, f"Password minimal {MIN_PASSWORD_LENGTH} karakter"

        entropy = cls.calculate_entropy(password)
        if entropy < MIN_ENTROPY_BITS:
            return False, f"Entropy password terlalu rendah ({entropy:.1f} bit, min {MIN_ENTROPY_BITS})"

        checks = [
            (any(c.islower() for c in password), "huruf kecil"),
            (any(c.isupper() for c in password), "huruf besar"),
            (any(c.isdigit() for c in password), "angka"),
            (any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password), "simbol"),
        ]
        missing = [name for is_ok, name in checks if not is_ok]
        if missing:
            return False, f"Password harus mengandung: {', '.join(missing)}"

        return True, f"Password kuat (entropy: {entropy:.1f} bit)"


# ══════════════════════════════════════════════════════════════════════════
# §5  RATE LIMITER (anti brute-force)
# ══════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """Melacak percobaan dekripsi gagal & menerapkan cooldown eksponensial.

    Path penyimpanan bisa dioverride (mis. untuk unit test) supaya tidak
    menyentuh file rate-limit asli di $HOME milik pengguna.
    """

    def __init__(self, storage_path: Path = DEFAULT_RATE_LIMIT_FILE):
        self.storage_path = Path(storage_path)

    def _load(self) -> Dict[str, Any]:
        try:
            if self.storage_path.exists():
                with open(self.storage_path, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return {"attempts": 0, "last_attempt": 0, "cooldown_until": 0}

    def _save(self, state: Dict[str, Any]) -> None:
        try:
            with open(self.storage_path, "w") as f:
                json.dump(state, f)
            os.chmod(self.storage_path, 0o600)
        except Exception:
            pass

    def check(self) -> Tuple[bool, int]:
        state = self._load()
        now = time.time()
        if now < state.get("cooldown_until", 0):
            return False, int(state["cooldown_until"] - now)
        if now - state.get("last_attempt", 0) > 3600:
            state["attempts"] = 0
        return True, 0

    def record_attempt(self, success: bool = False) -> None:
        state = self._load()
        now = time.time()
        if success:
            state["attempts"] = 0
            state["cooldown_until"] = 0
        else:
            state["attempts"] = state.get("attempts", 0) + 1
            state["last_attempt"] = now
            if state["attempts"] >= MAX_ATTEMPTS:
                multiplier = 2 ** (state["attempts"] - MAX_ATTEMPTS)
                state["cooldown_until"] = now + (COOLDOWN_BASE * multiplier)
        self._save(state)

    def get_status(self) -> str:
        state = self._load()
        now = time.time()
        cooldown = state.get("cooldown_until", 0)
        if now < cooldown:
            return f"Rate limit aktif -- tunggu {int(cooldown - now)} detik."
        return f"Attempts: {state.get('attempts', 0)}/{MAX_ATTEMPTS}"


# ══════════════════════════════════════════════════════════════════════════
# §6  KDF ENGINE (Argon2id prioritas, PBKDF2-HMAC-SHA512 fallback)
# ══════════════════════════════════════════════════════════════════════════

class KDFEngine:
    """Semua parameter KDF yang AKTUAL dipakai disimpan di header vault
    (bukan cuma dibaca dari konstanta modul saat dekripsi) -- supaya vault
    lama tetap bisa didekripsi walau konstanta default berubah di versi
    skrip berikutnya. Saat dekripsi, KDFEngine.derive() dipanggil dengan
    `params` hasil parse dari header, bukan dari ARGON2_* / PBKDF2_* global."""

    @staticmethod
    def preferred() -> int:
        return KDF_ARGON2ID if ARGON2_AVAILABLE else KDF_PBKDF2

    @staticmethod
    def default_params(kdf_id: int) -> Dict[str, Any]:
        if kdf_id == KDF_ARGON2ID:
            return {
                "type": "argon2id",
                "memory_cost": ARGON2_MEMORY_COST,
                "time_cost": ARGON2_TIME_COST,
                "parallelism": ARGON2_PARALLELISM,
                "hash_len": ARGON2_HASH_LEN,
            }
        elif kdf_id == KDF_PBKDF2:
            return {
                "type": "pbkdf2",
                "algorithm": "sha512",
                "iterations": PBKDF2_ITERATIONS,
                "length": AES_KEY_SIZE,
            }
        raise VaultError(f"KDF id {kdf_id} tidak dikenali.")

    @staticmethod
    def derive(password: bytes, salt: bytes, kdf_id: int, params: Dict[str, Any]) -> bytes:
        if kdf_id == KDF_ARGON2ID:
            if not ARGON2_AVAILABLE:
                raise VaultError(
                    "Vault ini memakai Argon2id tapi paket 'argon2-cffi' tidak "
                    "terpasang di sistem ini. Install dengan: pip install argon2-cffi"
                )
            return hash_secret_raw(
                secret=password,
                salt=salt,
                time_cost=params["time_cost"],
                memory_cost=params["memory_cost"],
                parallelism=params["parallelism"],
                hash_len=params["hash_len"],
                type=_Argon2Type.ID,
            )
        elif kdf_id == KDF_PBKDF2:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=params["length"],
                salt=salt,
                iterations=params["iterations"],
            )
            return kdf.derive(password)
        raise VaultError(f"KDF id {kdf_id} tidak dikenali oleh versi engine ini.")


# ══════════════════════════════════════════════════════════════════════════
# §7  KEY HIERARCHY (HKDF-SHA512 -- pisahkan kunci enkripsi & kunci HMAC)
# ══════════════════════════════════════════════════════════════════════════

def derive_subkeys(master_key: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    """Dari satu master key, turunkan DUA kunci independen: satu khusus
    AES-GCM, satu khusus HMAC-SHA512. Ini penting: kalau satu kunci dipakai
    untuk dua algoritma sekaligus, ada risiko teoretis interaksi antar
    algoritma yang melemahkan keduanya. Key-separation lewat HKDF
    menghilangkan risiko itu -- kompromi salah satu kunci turunan tidak
    otomatis membocorkan kunci turunan yang lain."""
    enc_key = HKDF(
        algorithm=hashes.SHA512(), length=AES_KEY_SIZE, salt=salt, info=b"godvault-enc-key-v2",
    ).derive(master_key)
    hmac_key = HKDF(
        algorithm=hashes.SHA512(), length=HMAC_KEY_SIZE, salt=salt, info=b"godvault-hmac-key-v2",
    ).derive(master_key)
    return enc_key, hmac_key


# ══════════════════════════════════════════════════════════════════════════
# §8  STREAM VAULT ENGINE — inti chunked encryption + counter-nonce
# ══════════════════════════════════════════════════════════════════════════
#
# Format vault (semua field big-endian):
#
#   MAGIC(4) VERSION(1) KDF_ID(1) KDF_PARAMS_LEN(2) KDF_PARAMS_JSON(var)
#   SALT_LEN(1) SALT(var) NONCE_PREFIX(4) COMPRESSED(1)
#   METADATA_LEN(2) METADATA_JSON(var)
#   -------------------------------- header selesai di sini -----------------
#   [CHUNK_0_LEN(4) CHUNK_0_CIPHERTEXT+TAG] [CHUNK_1_LEN(4) ...] ...
#   -------------------------------- akhir stream chunk ----------------------
#   GLOBAL_HMAC_SHA512(64)
#
# Nonce per chunk (96-bit AES-GCM) = NONCE_PREFIX(32-bit acak, sekali per
# vault) || COUNTER(64-bit big-endian, index chunk: 0,1,2,...) -- lihat
# penjelasan filosofi di docstring modul (§B di atas).
#
# AAD per chunk = header_bytes + chunk_index(8B) + is_last_flag(1B). Ini
# defense-in-depth: walau GLOBAL_HMAC (dicek LEBIH DULU, sebelum satu pun
# chunk didekripsi -- lihat _decrypt_stream) sudah menjamin seluruh byte
# stream identik-persis dengan yang ditulis pengenkripsi (jadi urutan &
# kelengkapan chunk otomatis terjamin), AAD ini membuat setiap chunk TETAP
# aman terverifikasi sendiri walau suatu saat varian lain dari engine ini
# dibuat tanpa lapis HMAC global.
# ══════════════════════════════════════════════════════════════════════════

_HEADER_FIXED_FMT = ">4sBBH"
_HEADER_FIXED_SIZE = struct.calcsize(_HEADER_FIXED_FMT)


def _make_nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack(">Q", counter)


def _chunk_aad(header_bytes: bytes, index: int, is_last: bool) -> bytes:
    return header_bytes + struct.pack(">QB", index, 1 if is_last else 0)


def _build_header(kdf_id: int, kdf_params: Dict[str, Any], salt: bytes,
                   nonce_prefix: bytes, compressed: bool, metadata: Dict[str, Any]) -> bytes:
    kdf_params_bytes = json.dumps(kdf_params, separators=(",", ":")).encode("utf-8")
    metadata_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")

    header = struct.pack(_HEADER_FIXED_FMT, MAGIC, VERSION, kdf_id, len(kdf_params_bytes))
    header += kdf_params_bytes
    header += struct.pack(">B", len(salt))
    header += salt
    header += nonce_prefix
    header += struct.pack(">B", 1 if compressed else 0)
    header += struct.pack(">H", len(metadata_bytes))
    header += metadata_bytes
    return header


def _read_header(f: BinaryIO) -> Tuple[Dict[str, Any], bytes]:
    """Baca & parse header LANGSUNG dari stream (file handle ATAU io.BytesIO),
    tanpa perlu memuat seluruh vault ke memori. Return (fields, raw_header_bytes).

    Semua kegagalan parsing (byte kurang, JSON rusak, dll -- termasuk yang
    dipicu oleh data yang sengaja dimanipulasi) dibungkus jadi VaultError
    yang seragam, supaya tidak ada exception mentah yang bocor ke pemanggil
    hanya karena header-nya rusak/dimanipulasi."""
    raw = bytearray()
    try:
        fixed = f.read(_HEADER_FIXED_SIZE)
        if len(fixed) != _HEADER_FIXED_SIZE:
            raise VaultError("Vault terlalu pendek / bukan format CRYPTO//GOD VAULT.")
        raw += fixed
        magic, version, kdf_id, kdf_params_len = struct.unpack(_HEADER_FIXED_FMT, fixed)
        if magic != MAGIC:
            raise VaultError("Bukan vault CRYPTO//GOD v2 (magic bytes tidak cocok).")
        if version != VERSION:
            raise VaultError(
                f"Vault versi {version} tidak didukung oleh engine ini (VERSION={VERSION}). "
                "Kemungkinan dibuat oleh versi skrip yang berbeda."
            )

        kdf_params_bytes = f.read(kdf_params_len)
        if len(kdf_params_bytes) != kdf_params_len:
            raise VaultError("Vault terpotong (parameter KDF tidak lengkap).")
        raw += kdf_params_bytes
        kdf_params = json.loads(kdf_params_bytes.decode("utf-8"))

        salt_len_b = f.read(1); raw += salt_len_b
        salt_len = salt_len_b[0]
        salt = f.read(salt_len)
        if len(salt) != salt_len:
            raise VaultError("Vault terpotong (salt tidak lengkap).")
        raw += salt

        nonce_prefix = f.read(NONCE_PREFIX_LEN)
        if len(nonce_prefix) != NONCE_PREFIX_LEN:
            raise VaultError("Vault terpotong (nonce prefix tidak lengkap).")
        raw += nonce_prefix

        compressed_b = f.read(1); raw += compressed_b
        compressed = bool(compressed_b[0])

        metadata_len_b = f.read(2); raw += metadata_len_b
        metadata_len = struct.unpack(">H", metadata_len_b)[0]
        metadata_bytes = f.read(metadata_len)
        if len(metadata_bytes) != metadata_len:
            raise VaultError("Vault terpotong (metadata tidak lengkap).")
        raw += metadata_bytes
        metadata = json.loads(metadata_bytes.decode("utf-8"))

        fields = {
            "kdf_id": kdf_id, "kdf_params": kdf_params, "salt": salt,
            "nonce_prefix": nonce_prefix, "compressed": compressed, "metadata": metadata,
        }
        return fields, bytes(raw)

    except VaultError:
        raise
    except Exception:
        # Byte kurang/acak bisa memicu berbagai exception mentah (struct.error,
        # UnicodeDecodeError, json.JSONDecodeError, IndexError, dst) --
        # semuanya berarti satu hal yang sama: header tidak valid/dimanipulasi.
        raise VaultError("Vault korup / bukan format CRYPTO//GOD VAULT yang valid.")


def _iter_payload_chunks(in_stream: BinaryIO, compress: bool, chunk_size: int,
                          read_block_size: int):
    """Generator yang menghasilkan (piece, is_last) -- potongan payload siap
    dienkripsi, masing-masing PERSIS chunk_size byte kecuali potongan
    TERAKHIR (boleh lebih pendek, bahkan 0 byte utk plaintext kosong).

    Kalau compress=True, payload dibentuk lewat zlib.compressobj() yang
    diberi makan sedikit-sedikit (bukan zlib.compress(seluruh_file) sekali
    jalan) -- jadi memori yang dipakai TIDAK proporsional dengan ukuran
    file, hanya proporsional dengan chunk_size + read_block_size. Ini
    murni perubahan CARA MENGHASILKAN byte payload; hasil akhirnya (dan
    dengan begitu format vault -- header, AAD, nonce, framing chunk, HMAC)
    sama sekali tidak berubah, karena deflate/zlib adalah format stream
    yang tidak peduli di batas byte mana ia "dipotong-potong" saat
    dikompres maupun didekompres. Vault lama yang dibuat dengan
    zlib.compress() sekali-jalan tetap terbaca normal oleh dekompresi
    streaming di _decrypt_chunks()."""
    compressor = zlib.compressobj(9) if compress else None
    pending = bytearray()

    while True:
        raw_block = in_stream.read(read_block_size)
        if raw_block:
            pending.extend(compressor.compress(raw_block) if compress else raw_block)
        else:
            if compress:
                pending.extend(compressor.flush())
            while len(pending) > chunk_size:
                piece = bytes(pending[:chunk_size])
                del pending[:chunk_size]
                yield piece, False
            yield bytes(pending), True
            return

        while len(pending) > chunk_size:
            piece = bytes(pending[:chunk_size])
            del pending[:chunk_size]
            yield piece, False


def _write_chunks_streaming(in_stream: BinaryIO, aesgcm: AESGCM, nonce_prefix: bytes,
                             header_bytes: bytes, chunk_size: int, compress: bool,
                             out_stream: BinaryIO, hmac_obj: "hmac.HMAC",
                             read_block_size: Optional[int] = None) -> None:
    """Enkripsi in_stream -> chunk demi chunk, memori terbatas ~chunk_size
    baik compress=True MAUPUN compress=False (lihat _iter_payload_chunks)."""
    read_block_size = read_block_size or chunk_size
    idx = 0
    for piece, is_last in _iter_payload_chunks(in_stream, compress, chunk_size, read_block_size):
        nonce = _make_nonce(nonce_prefix, idx)
        aad = _chunk_aad(header_bytes, idx, is_last)
        ct = aesgcm.encrypt(nonce, piece, aad)
        record = struct.pack(">I", len(ct)) + ct
        out_stream.write(record)
        hmac_obj.update(record)
        idx += 1


def _encrypt_stream(in_stream: BinaryIO, out_stream: BinaryIO, password: str, *,
                     compress: bool = True, metadata: Optional[Dict[str, Any]] = None,
                     chunk_size: int = DEFAULT_CHUNK_SIZE,
                     kdf_id: Optional[int] = None) -> None:
    """Enkripsi in_stream -> out_stream (format vault v2, TIDAK berubah).
    Fungsi ini murni mekanisme -- TIDAK menegakkan kebijakan password
    (lihat encrypt_bytes / encrypt_file untuk versi yang menegakkan
    PasswordValidator). Progress dilaporkan dengan membungkus in_stream
    di layer pemanggil (lihat encrypt_file / _ProgressReader), bukan di
    sini -- supaya fungsi ini tetap sederhana & dipakai juga oleh jalur
    teks (encrypt_bytes) yang tidak butuh progress."""
    kdf_id = kdf_id if kdf_id is not None else KDFEngine.preferred()
    kdf_params = KDFEngine.default_params(kdf_id)

    salt = secrets.token_bytes(SALT_LEN)
    nonce_prefix = secrets.token_bytes(NONCE_PREFIX_LEN)

    password_buf = bytearray(password.encode("utf-8"))
    try:
        master_key = KDFEngine.derive(bytes(password_buf), salt, kdf_id, kdf_params)
        enc_key, hmac_key = derive_subkeys(master_key, salt)

        meta = dict(metadata or {})
        meta.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

        header_bytes = _build_header(kdf_id, kdf_params, salt, nonce_prefix, compress, meta)
        out_stream.write(header_bytes)

        hmac_obj = hmac.new(hmac_key, digestmod=HMAC_HASH)
        hmac_obj.update(header_bytes)

        aesgcm = AESGCM(enc_key)
        _write_chunks_streaming(in_stream, aesgcm, nonce_prefix, header_bytes,
                                 chunk_size, compress, out_stream, hmac_obj)

        out_stream.write(hmac_obj.digest())
    finally:
        _wipe_bytes(password_buf)


def _verify_stream_hmac(in_stream: BinaryIO, hmac_key: bytes, header_bytes: bytes,
                         ciphertext_region_size: int, read_block: int = 1024 * 1024,
                         progress_cb: Optional[Callable[[int, int], None]] = None) -> None:
    """PASS 1: hitung & verifikasi HMAC-SHA512 global SEBELUM mendekripsi
    satu chunk pun. Ini mencegah plaintext yang belum terautentikasi
    sempat ditulis ke output (encrypt-then-MAC yang benar: verify dulu,
    baru decrypt). Memori terbatas ~read_block terlepas dari ukuran file."""
    hmac_obj = hmac.new(hmac_key, digestmod=HMAC_HASH)
    hmac_obj.update(header_bytes)

    remaining = ciphertext_region_size
    while remaining > 0:
        block = in_stream.read(min(read_block, remaining))
        if not block:
            raise VaultError("Vault terpotong / korup (ciphertext lebih pendek dari yang diharapkan).")
        hmac_obj.update(block)
        remaining -= len(block)
        if progress_cb:
            progress_cb(ciphertext_region_size - remaining, ciphertext_region_size)

    stored_hmac = in_stream.read(HMAC_DIGEST_SIZE)
    if len(stored_hmac) != HMAC_DIGEST_SIZE:
        raise VaultError("Vault terpotong / korup (HMAC penutup tidak lengkap).")

    if not hmac.compare_digest(hmac_obj.digest(), stored_hmac):
        raise VaultError("GAGAL! Password salah, atau data korup/dimanipulasi.")


def _feed_decompressor(decompressor: "zlib._Decompress", data: bytes,
                        out_stream: BinaryIO, max_length: int = DECOMPRESS_MAX_OUTPUT) -> None:
    """Umpankan `data` (bytes hasil dekripsi, masih terkompresi) ke
    decompressor & tulis progresif ke out_stream, DIBATASI max_length byte
    output per panggilan decompress().

    Kenapa ini penting: zlib.decompressobj().decompress(data) TANPA
    max_length akan mengembalikan SELURUH hasil dekompresi dari `data`
    dalam SATU alokasi memori sekaligus. Untuk data yang rasio
    kompresinya tinggi (wajar terjadi pada file yang sangat repetitif --
    bukan cuma skenario 'zip bomb' yang disengaja), satu chunk terenkripsi
    berukuran kecil bisa saja mengembang jadi ratusan MB output dalam satu
    panggilan, membuat penghematan memori dari streaming di tempat lain
    jadi percuma. `max_length` memaksa output dipotong per panggilan;
    sisa yang belum diproses ditampung zlib sendiri di
    `decompressor.unconsumed_tail` dan kita umpankan lagi sampai habis."""
    while True:
        out = decompressor.decompress(data, max_length)
        if out:
            out_stream.write(out)
        if not decompressor.unconsumed_tail:
            break
        data = decompressor.unconsumed_tail


def _decrypt_chunks(in_stream: BinaryIO, aesgcm: AESGCM, nonce_prefix: bytes,
                     header_bytes: bytes, ciphertext_region_size: int,
                     compressed: bool, out_stream: BinaryIO,
                     progress_cb: Optional[Callable[[int, int], None]] = None) -> None:
    """PASS 2: dipanggil HANYA setelah _verify_stream_hmac() lolos, jadi
    setiap chunk di sini dijamin identik-persis dengan hasil enkripsi asli
    (password sudah pasti benar juga, karena hmac_key & enc_key berasal
    dari master key yang sama).

    Dekompresi (kalau ada) sekarang JUGA streaming & DIBATASI per panggilan
    (lihat _feed_decompressor) -- ditulis progresif ke out_stream, tidak
    lagi menumpuk seluruh payload terkompresi ATAU seluruh hasil dekompresi
    di memori. Kompatibel penuh dengan vault lama (format kompresi tidak
    berubah, cuma cara membacanya yang sekarang bertahap & dibatasi)."""
    remaining = ciphertext_region_size
    idx = 0
    decompressor = zlib.decompressobj() if compressed else None

    while remaining > 0:
        len_bytes = in_stream.read(4)
        remaining -= 4
        (chunk_len,) = struct.unpack(">I", len_bytes)
        chunk_ct = in_stream.read(chunk_len)
        remaining -= chunk_len
        is_last = (remaining == 0)

        nonce = _make_nonce(nonce_prefix, idx)
        aad = _chunk_aad(header_bytes, idx, is_last)
        plaintext_piece = aesgcm.decrypt(nonce, chunk_ct, aad)

        if compressed:
            _feed_decompressor(decompressor, plaintext_piece, out_stream)
        else:
            out_stream.write(plaintext_piece)
        idx += 1

        if progress_cb:
            progress_cb(ciphertext_region_size - remaining, ciphertext_region_size)

    if compressed:
        # Setelah semua chunk diumpankan & dikuras lewat _feed_decompressor,
        # flush() hanya menyisakan (kalau ada) beberapa byte penutup
        # trailer zlib -- bukan sisa data terdekompresi dalam jumlah besar.
        out_stream.write(decompressor.flush())


def _decrypt_stream(in_stream: BinaryIO, total_size: int, out_stream: BinaryIO,
                     password: str,
                     progress_cb: Optional[Callable[[str, int, int], None]] = None) -> Dict[str, Any]:
    header_start = in_stream.tell()
    fields, header_bytes = _read_header(in_stream)
    header_end = in_stream.tell()

    ciphertext_region_size = total_size - (header_end - header_start) - HMAC_DIGEST_SIZE
    if ciphertext_region_size < 0:
        raise VaultError("Vault terlalu pendek / bukan format yang valid.")

    password_buf = bytearray(password.encode("utf-8"))
    try:
        master_key = KDFEngine.derive(bytes(password_buf), fields["salt"],
                                       fields["kdf_id"], fields["kdf_params"])
        enc_key, hmac_key = derive_subkeys(master_key, fields["salt"])

        verify_cb = (lambda done, total: progress_cb("verify", done, total)) if progress_cb else None
        _verify_stream_hmac(in_stream, hmac_key, header_bytes, ciphertext_region_size,
                             progress_cb=verify_cb)

        in_stream.seek(header_end)
        aesgcm = AESGCM(enc_key)
        decrypt_cb = (lambda done, total: progress_cb("decrypt", done, total)) if progress_cb else None
        _decrypt_chunks(in_stream, aesgcm, fields["nonce_prefix"], header_bytes,
                         ciphertext_region_size, fields["compressed"], out_stream,
                         progress_cb=decrypt_cb)

        return fields["metadata"]
    finally:
        _wipe_bytes(password_buf)


# ══════════════════════════════════════════════════════════════════════════
# §8b  PROGRESS BAR (untuk operasi FILE -- teks/pesan tidak butuh ini)
# ══════════════════════════════════════════════════════════════════════════

class _ProgressReader:
    """Bungkus stream input yang punya .read() dan lapor progres lewat
    callback tiap kali .read() dipanggil. Transparan -- perilaku .read()
    itu sendiri tidak berubah sama sekali, cuma nge-hook progres. Dipakai
    untuk melaporkan progres ENKRIPSI (baca file asli), karena proses
    enkripsi murni satu arah/satu-pass (tidak seperti dekripsi yang
    2-pass -- lihat _decrypt_stream)."""

    def __init__(self, stream: BinaryIO, total: int, callback: Callable[[int, int], None]):
        self._stream = stream
        self._total = total
        self._callback = callback
        self._done = 0

    def read(self, n: int = -1) -> bytes:
        chunk = self._stream.read(n)
        self._done += len(chunk)
        self._callback(self._done, self._total)
        return chunk


def _format_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TiB"


def make_file_progress_printer() -> Callable[[str, int, int], None]:
    """Return callback progress_cb(stage, done, total) yang menggambar
    progress bar teks di terminal (auto nonaktif kalau bukan TTY, mis.
    output di-pipe). 'stage' dipakai untuk mode dekripsi yang 2 tahap:
    'read' (baca+enkripsi), 'verify' (cek HMAC), 'decrypt' (dekripsi+tulis)
    -- tiap pergantian stage mulai baris progress baru."""
    is_tty = sys.stdout.isatty()
    STAGE_LABEL = {
        "read": "Membaca & mengenkripsi",
        "verify": "Memverifikasi integritas",
        "decrypt": "Mendekripsi & menulis",
    }
    state: Dict[str, Any] = {"stage": None, "start": 0.0, "last_print": 0.0}

    def cb(stage: str, done: int, total: int) -> None:
        if not is_tty or total <= 0:
            return
        now = time.time()

        if state["stage"] != stage:
            if state["stage"] is not None:
                sys.stdout.write("\n")
            state["stage"] = stage
            state["start"] = now
            state["last_print"] = 0.0

        finished = done >= total
        if not finished and now - state["last_print"] < 0.08:
            return
        state["last_print"] = now

        frac = min(1.0, done / total)
        width = 28
        filled = int(width * frac)
        bar = "█" * filled + "░" * (width - filled)
        elapsed = max(now - state["start"], 1e-6)
        speed = done / elapsed
        eta = (total - done) / speed if speed > 0 else 0
        label = STAGE_LABEL.get(stage, stage)

        sys.stdout.write(
            f"\r{C.CYAN}{label}{C.RESET} [{C.GREEN}{bar}{C.RESET}] "
            f"{frac * 100:5.1f}%  {_format_bytes(done)}/{_format_bytes(total)}  "
            f"{_format_bytes(speed)}/s  ETA {int(eta)}s   "
        )
        sys.stdout.flush()
        if finished:
            sys.stdout.write("\n")
            sys.stdout.flush()

    return cb


# ══════════════════════════════════════════════════════════════════════════
# §9  API TINGKAT TINGGI — TEKS & FILE
# ══════════════════════════════════════════════════════════════════════════

def encrypt_bytes(data: bytes, password: str, *, compress: bool = True,
                   metadata: Optional[Dict[str, Any]] = None,
                   chunk_size: int = DEFAULT_CHUNK_SIZE,
                   kdf_id: Optional[int] = None,
                   enforce_policy: bool = True) -> bytes:
    if enforce_policy:
        valid, msg = PasswordValidator.validate(password)
        if not valid:
            raise VaultError(f"Password lemah: {msg}")
    out_stream = io.BytesIO()
    _encrypt_stream(io.BytesIO(data), out_stream, password, compress=compress,
                     metadata=metadata, chunk_size=chunk_size, kdf_id=kdf_id)
    return out_stream.getvalue()


def decrypt_bytes(blob: bytes, password: str) -> Tuple[bytes, Dict[str, Any]]:
    out_stream = io.BytesIO()
    try:
        metadata = _decrypt_stream(io.BytesIO(blob), len(blob), out_stream, password)
    except VaultError:
        raise
    except Exception:
        # Jaring pengaman terakhir: apa pun yang tidak terduga saat parsing
        # data yang tidak tepercaya harus tetap muncul sebagai VaultError,
        # bukan traceback mentah.
        raise VaultError("Vault korup / bukan format CRYPTO//GOD VAULT yang valid.")
    return out_stream.getvalue(), metadata


def encrypt_message(message: str, password: str, *, compress: bool = True,
                     enforce_policy: bool = True) -> str:
    """Enkripsi teks -> string base64 yang aman ditempel/disalin di mana saja."""
    try:
        blob = encrypt_bytes(message.encode("utf-8"), password, compress=compress,
                              enforce_policy=enforce_policy)
        return base64.urlsafe_b64encode(blob).decode("ascii")
    except VaultError as e:
        return f"[ERROR] {e}"
    except Exception as e:
        return f"[ERROR] Gagal mengenkripsi: {e}"


def decrypt_message(encrypted_message: str, password: str) -> str:
    """Dekripsi string base64 hasil encrypt_message()."""
    try:
        blob = base64.urlsafe_b64decode(encrypted_message.strip().encode("ascii"))
        plaintext, _meta = decrypt_bytes(blob, password)
        return plaintext.decode("utf-8")
    except VaultError as e:
        return f"[ERROR] {e}"
    except Exception as e:
        return f"[ERROR] Terjadi kesalahan: {e}"


def encrypt_file(in_path, out_path, password: str, *, compress: bool = True,
                  chunk_size: int = DEFAULT_CHUNK_SIZE, kdf_id: Optional[int] = None,
                  enforce_policy: bool = True, delete_source: bool = False,
                  progress_cb: Optional[Callable[[str, int, int], None]] = None) -> None:
    """Enkripsi file APA PUN ke format vault. Sepenuhnya streaming dengan
    memori nyaris konstan (tidak proporsional dengan ukuran file), baik
    compress=True maupun compress=False -- aman untuk file berukuran
    berapa pun selama ada ruang disk cukup untuk output-nya.

    progress_cb, kalau diisi, dipanggil sbg progress_cb("read", done, total)
    seiring file dibaca & dienkripsi (lihat make_file_progress_printer())."""
    if enforce_policy:
        valid, msg = PasswordValidator.validate(password)
        if not valid:
            raise VaultError(f"Password lemah: {msg}")

    in_path = Path(in_path)
    total_size = in_path.stat().st_size
    metadata = {"filename": in_path.name, "source_size": total_size}

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        source: BinaryIO = fin
        if progress_cb:
            source = _ProgressReader(fin, total_size,
                                      lambda done, total: progress_cb("read", done, total))
        _encrypt_stream(source, fout, password, compress=compress, metadata=metadata,
                         chunk_size=chunk_size, kdf_id=kdf_id)

    if delete_source:
        _secure_delete(in_path)


def decrypt_file(in_path, out_path, password: str,
                  progress_cb: Optional[Callable[[str, int, int], None]] = None) -> Dict[str, Any]:
    """Dekripsi file vault. Sepenuhnya streaming dengan memori nyaris
    konstan (dua pass dibaca dari disk, bukan dari RAM -- lihat
    _decrypt_stream: pass 1 verifikasi HMAC, pass 2 dekripsi+tulis).

    progress_cb, kalau diisi, dipanggil sbg progress_cb(stage, done, total)
    dengan stage "verify" lalu "decrypt" (lihat make_file_progress_printer())."""
    in_path = Path(in_path)
    total_size = in_path.stat().st_size
    try:
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            metadata = _decrypt_stream(fin, total_size, fout, password, progress_cb=progress_cb)
    except VaultError:
        # Gagal -- hapus file output parsial (kalau ada) supaya tidak
        # meninggalkan plaintext yang belum terautentikasi penuh di disk.
        Path(out_path).unlink(missing_ok=True)
        raise
    except OSError:
        raise
    except Exception:
        Path(out_path).unlink(missing_ok=True)
        raise VaultError("Vault korup / bukan format CRYPTO//GOD VAULT yang valid.")
    return metadata


def _secure_delete(path: Path, passes: int = 3) -> None:
    """Overwrite file dengan data acak beberapa kali sebelum dihapus.
    Catatan jujur: pada SSD modern (wear-leveling) dan filesystem
    copy-on-write, ini tidak menjamin data lama benar-benar tak terlacak --
    tapi tetap jauh lebih baik daripada delete biasa di HDD/filesystem
    tradisional."""
    path = Path(path)
    if not path.exists():
        return
    size = path.stat().st_size
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            f.write(secrets.token_bytes(size))
            f.flush()
            os.fsync(f.fileno())
    path.unlink()


# ══════════════════════════════════════════════════════════════════════════
# §10  UTILITAS PASSWORD (generator, dari CRYPTO//GOD)
# ══════════════════════════════════════════════════════════════════════════

def generate_strong_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ══════════════════════════════════════════════════════════════════════════
# §11  MENU INTERAKTIF
# ══════════════════════════════════════════════════════════════════════════

def _ask_password_confirmed() -> str:
    while True:
        pwd1 = getpass.getpass("Buat password: ")
        if len(pwd1) == 0:
            error("Password tidak boleh kosong.\n")
            continue

        valid, msg = PasswordValidator.validate(pwd1)
        if valid:
            ok(msg)
        else:
            warn(msg)
            lanjut = input("Tetap pakai password ini? (y/N): ").strip().lower()
            if lanjut != "y":
                continue

        pwd2 = getpass.getpass("Ulangi password: ")
        if pwd1 != pwd2:
            error("Password tidak sama, coba lagi.\n")
            continue
        return pwd1


def menu_encrypt_text() -> None:
    pesan = input("Masukkan pesan rahasia Anda: ")
    pwd = _ask_password_confirmed()
    hasil = encrypt_message(pesan, pwd, enforce_policy=False)  # sudah divalidasi di atas
    print(f"\n{C.BOLD}--- HASIL ENKRIPSI ---{C.RESET}")
    print(hasil)


def menu_decrypt_text() -> None:
    limiter = RateLimiter()
    allowed, wait = limiter.check()
    if not allowed:
        error(f"Rate limit aktif. Tunggu {wait} detik sebelum mencoba lagi.")
        return

    pesan_enkripsi = input("Tempel (paste) vault terenkripsi: ")
    pwd = getpass.getpass("Masukkan password: ")
    hasil = decrypt_message(pesan_enkripsi, pwd)

    print(f"\n{C.BOLD}--- HASIL TERJEMAHAN ---{C.RESET}")
    if hasil.startswith("[ERROR]"):
        error(hasil)
        limiter.record_attempt(success=False)
    else:
        print(hasil)
        limiter.record_attempt(success=True)


def menu_encrypt_file() -> None:
    in_path = input("Path file yang mau dienkripsi: ").strip()
    if not os.path.isfile(in_path):
        error("File tidak ditemukan.")
        return
    out_path = input(f"Path output [{in_path}.vault]: ").strip() or f"{in_path}.vault"
    pwd = _ask_password_confirmed()
    compress = input("Kompresi sebelum enkripsi? (Y/n): ").strip().lower() != "n"

    try:
        encrypt_file(in_path, out_path, pwd, compress=compress, enforce_policy=False,
                     progress_cb=make_file_progress_printer())
        ok(f"File terenkripsi disimpan di: {out_path}")
    except Exception as e:
        error(f"Gagal mengenkripsi file: {e}")


def menu_decrypt_file() -> None:
    limiter = RateLimiter()
    allowed, wait = limiter.check()
    if not allowed:
        error(f"Rate limit aktif. Tunggu {wait} detik sebelum mencoba lagi.")
        return

    in_path = input("Path file vault (.vault): ").strip()
    if not os.path.isfile(in_path):
        error("File tidak ditemukan.")
        return
    default_out = in_path[:-6] if in_path.endswith(".vault") else f"{in_path}.dec"
    out_path = input(f"Path output [{default_out}]: ").strip() or default_out
    pwd = getpass.getpass("Masukkan password: ")

    try:
        decrypt_file(in_path, out_path, pwd, progress_cb=make_file_progress_printer())
        ok(f"File hasil dekripsi disimpan di: {out_path}")
        limiter.record_attempt(success=True)
    except VaultError as e:
        error(str(e))
        limiter.record_attempt(success=False)
    except Exception as e:
        error(f"Terjadi kesalahan: {e}")


def menu_generate_password() -> None:
    raw = input("Panjang password [24]: ").strip()
    try:
        length = int(raw) if raw else 24
    except ValueError:
        length = 24
    pwd = generate_strong_password(length)
    bits = PasswordValidator.calculate_entropy(pwd)
    info(f"Estimasi entropy: ~{bits:.0f} bit")
    warn("SIMPAN password ini SEKARANG. Tidak akan ditampilkan lagi.")
    print(f"{C.BOLD}{C.GREEN}{pwd}{C.RESET}")


def menu_status() -> None:
    info(RateLimiter().get_status())
    info(f"KDF aktif: {'Argon2id' if ARGON2_AVAILABLE else f'PBKDF2-SHA512 ({PBKDF2_ITERATIONS:,} iter, fallback)'}")


def interactive_menu() -> None:
    banner()
    kdf_name = "Argon2id" if ARGON2_AVAILABLE else f"PBKDF2-SHA512 ({PBKDF2_ITERATIONS:,} iter, fallback)"
    info(f"KDF aktif: {kdf_name}")
    if not ARGON2_AVAILABLE:
        warn("argon2-cffi tidak terpasang -- pakai 'pip install argon2-cffi' untuk KDF terkuat.")

    while True:
        print(f"\n{C.CYAN} (m){C.RESET} Enkripsi teks")
        print(f"{C.CYAN} (j){C.RESET} Dekripsi teks")
        print(f"{C.CYAN} (f){C.RESET} Enkripsi file")
        print(f"{C.CYAN} (d){C.RESET} Dekripsi file")
        print(f"{C.CYAN} (g){C.RESET} Generate password acak")
        print(f"{C.CYAN} (s){C.RESET} Status rate-limiter")
        print(f"{C.CYAN} (q){C.RESET} Keluar")
        pilihan = input("\nPilih: ").strip().lower()
        print()

        if pilihan == "m":
            menu_encrypt_text()
        elif pilihan == "j":
            menu_decrypt_text()
        elif pilihan == "f":
            menu_encrypt_file()
        elif pilihan == "d":
            menu_decrypt_file()
        elif pilihan == "g":
            menu_generate_password()
        elif pilihan == "s":
            menu_status()
        elif pilihan == "q":
            print("Sampai jumpa.")
            break
        else:
            warn("Pilihan tidak valid.")
        print()


# ══════════════════════════════════════════════════════════════════════════
# §12  CLI (argparse, untuk scripting / pemakaian non-interaktif)
# ══════════════════════════════════════════════════════════════════════════

def _kdf_id_from_name(name: Optional[str]) -> Optional[int]:
    if name is None:
        return None
    return {"argon2id": KDF_ARGON2ID, "pbkdf2": KDF_PBKDF2}[name]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crypto_god_vault.py",
        description="CRYPTO//GOD VAULT v3.0 -- AES-256-GCM + Argon2id/PBKDF2 + HKDF + "
                     "HMAC-SHA512 ganda + counter-nonce. Jalankan tanpa argumen untuk menu interaktif.",
    )
    sub = p.add_subparsers(dest="command")

    enc = sub.add_parser("enc", help="Enkripsi teks atau file")
    grp = enc.add_mutually_exclusive_group(required=True)
    grp.add_argument("-m", "--message", help="Teks yang mau dienkripsi")
    grp.add_argument("-i", "--input", help="Path file yang mau dienkripsi")
    enc.add_argument("-o", "--output", help="Path file output (mode file)")
    enc.add_argument("--no-compress", action="store_true", help="Nonaktifkan kompresi zlib")
    enc.add_argument("--force", action="store_true", help="Lewati validasi kekuatan password")
    enc.add_argument("--kdf", choices=["argon2id", "pbkdf2"],
                      help="Paksa KDF tertentu (default: Argon2id kalau tersedia)")

    dec = sub.add_parser("dec", help="Dekripsi teks atau file")
    grp2 = dec.add_mutually_exclusive_group(required=True)
    grp2.add_argument("-m", "--message", help="Teks vault (base64)")
    grp2.add_argument("-i", "--input", help="Path file vault")
    dec.add_argument("-o", "--output", help="Path file output (mode file)")

    genp = sub.add_parser("genpass", help="Buat password acak yang kuat")
    genp.add_argument("-l", "--length", type=int, default=24)

    sub.add_parser("status", help="Lihat status rate-limiter & KDF aktif")

    return p


def run_cli(args: argparse.Namespace) -> int:
    if args.command == "enc":
        kdf_id = _kdf_id_from_name(args.kdf)
        if kdf_id == KDF_ARGON2ID and not ARGON2_AVAILABLE:
            error("Argon2id diminta tapi argon2-cffi belum terpasang (pip install argon2-cffi).")
            return 1

        pwd = getpass.getpass("Password: ")
        try:
            if args.message is not None:
                hasil = encrypt_message(args.message, pwd, compress=not args.no_compress,
                                         enforce_policy=not args.force)
                if hasil.startswith("[ERROR]"):
                    error(hasil)
                    return 1
                print(hasil)
            else:
                out = args.output or f"{args.input}.vault"
                encrypt_file(args.input, out, pwd, compress=not args.no_compress,
                              kdf_id=kdf_id, enforce_policy=not args.force,
                              progress_cb=make_file_progress_printer())
                ok(f"Tersimpan di {out}")
        except VaultError as e:
            error(str(e))
            return 1
        except OSError as e:
            error(f"Gagal membaca/menulis file: {e}")
            return 1
        return 0

    if args.command == "dec":
        limiter = RateLimiter()
        allowed, wait = limiter.check()
        if not allowed:
            error(f"Rate limit aktif. Tunggu {wait} detik.")
            return 1

        pwd = getpass.getpass("Password: ")
        try:
            if args.message is not None:
                hasil = decrypt_message(args.message, pwd)
                if hasil.startswith("[ERROR]"):
                    error(hasil)
                    limiter.record_attempt(success=False)
                    return 1
                print(hasil)
                limiter.record_attempt(success=True)
            else:
                out = args.output or (args.input[:-6] if args.input.endswith(".vault") else f"{args.input}.dec")
                decrypt_file(args.input, out, pwd, progress_cb=make_file_progress_printer())
                ok(f"Tersimpan di {out}")
                limiter.record_attempt(success=True)
        except VaultError as e:
            error(str(e))
            limiter.record_attempt(success=False)
            return 1
        except OSError as e:
            error(f"Gagal membaca/menulis file: {e}")
            return 1
        return 0

    if args.command == "genpass":
        pwd = generate_strong_password(args.length)
        bits = PasswordValidator.calculate_entropy(pwd)
        info(f"Entropy: ~{bits:.0f} bit")
        print(pwd)
        return 0

    if args.command == "status":
        info(RateLimiter().get_status())
        info(f"KDF aktif: {'Argon2id' if ARGON2_AVAILABLE else f'PBKDF2-SHA512 ({PBKDF2_ITERATIONS:,} iter, fallback)'}")
        return 0

    return 1


# ══════════════════════════════════════════════════════════════════════════
# §13  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        interactive_menu()
        return

    sys.exit(run_cli(args))


if __name__ == "__main__":
    main()
