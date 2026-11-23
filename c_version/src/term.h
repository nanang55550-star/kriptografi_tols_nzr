#ifndef GODVAULT_TERM_H
#define GODVAULT_TERM_H

#include <stddef.h>

/* Baca password TANPA echo ke layar (mematikan termios ECHO sementara).
 * Return buffer malloc'd (caller WAJIB gv_wipe() lalu free() setelah
 * dipakai). NULL kalau gagal alokasi/baca. */
char *gv_read_password(const char *prompt);

/* Baca satu baris input biasa (echo normal). Buffer malloc'd, caller free(). */
char *gv_read_line(const char *prompt);

int  gv_stdout_is_tty(void);
void gv_print_banner(void);
void gv_info(const char *fmt, ...);
void gv_ok(const char *fmt, ...);
void gv_warn(const char *fmt, ...);
void gv_error(const char *fmt, ...);

#endif /* GODVAULT_TERM_H */
