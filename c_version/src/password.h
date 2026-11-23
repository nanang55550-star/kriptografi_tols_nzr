#ifndef GODVAULT_PASSWORD_H
#define GODVAULT_PASSWORD_H

#include <stddef.h>
#include <stdbool.h>

/* Estimasi entropi kasar (heuristik: charset x panjang, penalti karakter
 * berulang, penalti pola sekuensial) -- port langsung dari validator versi
 * Python, BUKAN pengganti alat seperti zxcvbn. */
double gv_password_entropy(const char *password);

/* Return true kalau password memenuhi kebijakan minimum (panjang >=12,
 * entropi >=50 bit, mengandung huruf besar+kecil+angka+simbol).
 * reason_out (opsional) diisi pesan singkat kalau gagal. */
bool gv_password_validate(const char *password, char *reason_out, size_t reason_cap);

/* Password acak kriptografis (OpenSSL RAND_bytes + rejection sampling,
 * BUKAN rand()/modulo biasa -- menghindari modulo bias). out harus
 * buffer >= length+1 byte (utk null terminator). Return true kalau sukses. */
bool gv_password_generate(char *out, size_t length);

#endif /* GODVAULT_PASSWORD_H */
