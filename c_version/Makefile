# ==============================================================================
# Makefile — CRYPTO//GOD VAULT (C EDITION)
# ==============================================================================
# Target: Linux desktop, macOS, Termux (Android).
#
# Dependensi WAJIB : OpenSSL (libssl/libcrypto), zlib
# Dependensi OPSIONAL: libargon2 (kalau tidak ada, build otomatis fallback
#                       ke PBKDF2-HMAC-SHA512 saja -- lihat deteksi di bawah)
#
# Instalasi dependensi:
#   Debian/Ubuntu : sudo apt install build-essential libssl-dev libargon2-dev zlib1g-dev
#   Termux        : pkg install clang openssl argon2 zlib pkg-config make
#   macOS(brew)   : brew install openssl@3 argon2 zlib pkg-config
#                   (mungkin perlu: export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig:$(brew --prefix argon2)/lib/pkgconfig")
#
# Build:
#   make            # build biner ke bin/godvaultc
#   make test       # build & jalankan seluruh unit test
#   make clean
# ==============================================================================

CC       ?= cc
SRC_DIR  := src
TEST_DIR := tests
BUILD_DIR:= build
BIN_DIR  := bin

CFLAGS   ?= -std=c11 -Wall -Wextra -O2 -D_FILE_OFFSET_BITS=64 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
LDFLAGS  ?=

# ---- Deteksi pkg-config utk openssl & zlib (portable Linux/macOS/Termux) ----
PKGCONFIG ?= pkg-config

OPENSSL_CFLAGS := $(shell $(PKGCONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell $(PKGCONFIG) --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
  OPENSSL_LIBS := -lssl -lcrypto
endif

ZLIB_CFLAGS := $(shell $(PKGCONFIG) --cflags zlib 2>/dev/null)
ZLIB_LIBS   := $(shell $(PKGCONFIG) --libs zlib 2>/dev/null)
ifeq ($(strip $(ZLIB_LIBS)),)
  ZLIB_LIBS := -lz
endif

# ---- Deteksi libargon2 (opsional) -------------------------------------------
ARGON2_LIBS := $(shell $(PKGCONFIG) --libs libargon2 2>/dev/null)
HAVE_ARGON2 := $(shell $(PKGCONFIG) --exists libargon2 2>/dev/null && echo 1)
ifneq ($(HAVE_ARGON2),1)
  # fallback: cek header/lib manual kalau pkg-config tidak tahu libargon2
  HAVE_ARGON2 := $(shell echo '\#include <argon2.h>' | $(CC) -E - >/dev/null 2>&1 && echo 1)
  ifeq ($(HAVE_ARGON2),1)
    ARGON2_LIBS := -largon2
  endif
endif

ifeq ($(HAVE_ARGON2),1)
  CFLAGS += -DGV_WITH_ARGON2
  EXTRA_LIBS := $(ARGON2_LIBS)
else
  $(warning libargon2 tidak ditemukan -- build TANPA Argon2id, fallback PBKDF2-SHA512 saja. \
            Install libargon2-dev (Debian/Ubuntu) / argon2 (Termux) / argon2 (macOS brew) utk KDF terkuat.)
  EXTRA_LIBS :=
endif

CFLAGS  += -I$(SRC_DIR) $(OPENSSL_CFLAGS) $(ZLIB_CFLAGS)
LDLIBS  := $(OPENSSL_LIBS) $(ZLIB_LIBS) $(EXTRA_LIBS) -lm

CORE_SRCS := $(filter-out $(SRC_DIR)/main.c, $(wildcard $(SRC_DIR)/*.c))
CORE_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(CORE_SRCS))
MAIN_OBJ  := $(BUILD_DIR)/main.o

TARGET := $(BIN_DIR)/godvaultc
TEST_TARGET := $(BIN_DIR)/test_vault

.PHONY: all clean test

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(CORE_OBJS) $(MAIN_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(CORE_OBJS) $(MAIN_OBJ) -o $@ $(LDLIBS) $(LDFLAGS)

$(TEST_TARGET): $(CORE_OBJS) $(TEST_DIR)/test_vault.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $(CORE_OBJS) $(TEST_DIR)/test_vault.c -o $@ $(LDLIBS) $(LDFLAGS)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
