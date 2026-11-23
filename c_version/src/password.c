#include "password.h"
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <openssl/rand.h>

#define GV_PW_MIN_LEN     12
#define GV_PW_MIN_ENTROPY 50.0

static const char SYMBOLS[] = "!@#$%^&*()_+-=[]{}|;:,.<>?";

double gv_password_entropy(const char *password) {
    size_t len = strlen(password);
    if (len == 0) return 0.0;

    int has_lower = 0, has_upper = 0, has_digit = 0, has_symbol = 0, has_unicode = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        if (c >= 128) { has_unicode = 1; continue; }
        if (islower(c)) has_lower = 1;
        else if (isupper(c)) has_upper = 1;
        else if (isdigit(c)) has_digit = 1;
        else if (strchr(SYMBOLS, (int)c)) has_symbol = 1;
    }

    int pool = 0;
    if (has_lower) pool += 26;
    if (has_upper) pool += 26;
    if (has_digit) pool += 10;
    if (has_symbol) pool += 32;
    if (has_unicode) pool += 50;
    if (pool == 0) return 0.0;

    double entropy = (double)len * (log((double)pool) / log(2.0));

    /* Penalti karakter unik: charset unik / panjang (versi byte-based,
     * cukup dekat dgn versi Python yg berbasis code point utk kasus ASCII
     * yg mendominasi pemakaian password). */
    int seen[256] = {0};
    int unique = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        if (!seen[c]) { seen[c] = 1; unique++; }
    }
    entropy *= (double)unique / (double)len;

    /* Penalti pola sekuensial (mis. "abc", "123") */
    int seq_penalty = 0;
    for (size_t i = 0; i + 2 < len; i++) {
        int d1 = (unsigned char)password[i + 1] - (unsigned char)password[i];
        int d2 = (unsigned char)password[i + 2] - (unsigned char)password[i + 1];
        if (d1 == d2) seq_penalty++;
    }
    double seq_factor = 1.0 - ((double)seq_penalty / (double)len);
    if (seq_factor < 0.3) seq_factor = 0.3;
    entropy *= seq_factor;

    return entropy;
}

bool gv_password_validate(const char *password, char *reason_out, size_t reason_cap) {
    size_t len = strlen(password);
    if (len < GV_PW_MIN_LEN) {
        if (reason_out) snprintf(reason_out, reason_cap, "Password minimal %d karakter", GV_PW_MIN_LEN);
        return false;
    }

    double entropy = gv_password_entropy(password);
    if (entropy < GV_PW_MIN_ENTROPY) {
        if (reason_out)
            snprintf(reason_out, reason_cap, "Entropy password terlalu rendah (%.1f bit, min %.0f)",
                     entropy, GV_PW_MIN_ENTROPY);
        return false;
    }

    int has_lower = 0, has_upper = 0, has_digit = 0, has_symbol = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        if (islower(c)) has_lower = 1;
        else if (isupper(c)) has_upper = 1;
        else if (isdigit(c)) has_digit = 1;
        else if (c < 128 && strchr(SYMBOLS, (int)c)) has_symbol = 1;
    }

    if (!(has_lower && has_upper && has_digit && has_symbol)) {
        if (reason_out) {
            char buf[128] = "Password harus mengandung: ";
            int first = 1;
            if (!has_lower)  { strcat(buf, first ? "huruf kecil" : ", huruf kecil"); first = 0; }
            if (!has_upper)  { strcat(buf, first ? "huruf besar" : ", huruf besar"); first = 0; }
            if (!has_digit)  { strcat(buf, first ? "angka" : ", angka"); first = 0; }
            if (!has_symbol) { strcat(buf, first ? "simbol" : ", simbol"); first = 0; }
            snprintf(reason_out, reason_cap, "%s", buf);
        }
        return false;
    }

    if (reason_out) snprintf(reason_out, reason_cap, "Password kuat (entropy: %.1f bit)", entropy);
    return true;
}

bool gv_password_generate(char *out, size_t length) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "!@#$%^&*()-_=+[]{}";
    const size_t alphabet_len = sizeof(alphabet) - 1; /* tanpa null terminator */

    /* Rejection sampling: buang byte acak yg >= largest_multiple, supaya
     * pemetaan byte->indeks alfabet BENAR-BENAR seragam (hindari modulo
     * bias -- byte % alphabet_len saja akan sedikit condong ke indeks
     * kecil kalau 256 tidak habis dibagi alphabet_len). */
    unsigned char threshold = (unsigned char)(256 - (256 % alphabet_len));

    for (size_t i = 0; i < length; i++) {
        unsigned char b;
        do {
            if (RAND_bytes(&b, 1) != 1) return false;
        } while (b >= threshold);
        out[i] = alphabet[b % alphabet_len];
    }
    out[length] = '\0';
    return true;
}
