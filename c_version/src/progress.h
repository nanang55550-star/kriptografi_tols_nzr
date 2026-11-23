#ifndef GODVAULT_PROGRESS_H
#define GODVAULT_PROGRESS_H

#include <stdint.h>

/* Progress bar teks di terminal, dgn transisi tahap (dipakai dekripsi yg
 * 2-pass: "verify" lalu "decrypt"). Otomatis nonaktif kalau stdout bukan
 * TTY (mis. output di-pipe) -- dipanggil sbg gv_progress_cb standar,
 * cocok langsung dioper ke gv_encrypt_stream/gv_decrypt_stream dkk. */
typedef struct {
    int is_tty;
    char stage[32];
    double start_time;
    double last_print;
} gv_progress_printer_t;

void gv_progress_printer_init(gv_progress_printer_t *p);

/* Signature ini cocok dgn gv_progress_cb di vault_api.h -- oper `p` sbg ctx. */
void gv_progress_printer_cb(const char *stage, uint64_t done, uint64_t total, void *ctx);

#endif /* GODVAULT_PROGRESS_H */
