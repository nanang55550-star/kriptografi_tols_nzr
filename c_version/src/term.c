#include "term.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <termios.h>

int gv_stdout_is_tty(void) {
    return isatty(fileno(stdout));
}

/* Dipakai utk keputusan warna ANSI pada pesan status/banner, yg SEKARANG
 * dikirim ke stderr (bukan stdout) -- lihat print_tagged/gv_print_banner
 * di bawah. Ini standar praktik CLI: stdout HANYA utk data hasil (mis.
 * ciphertext base64, plaintext hasil dekripsi) supaya aman dipipe/redirect
 * tanpa tercampur teks prompt/status; stderr utk semua komunikasi ke
 * manusia. */
static int stderr_is_tty(void) {
    return isatty(fileno(stderr));
}

static int stdin_is_tty(void) {
    return isatty(fileno(stdin));
}

char *gv_read_password(const char *prompt) {
    if (prompt) { fputs(prompt, stderr); fflush(stderr); }

    struct termios old_t, new_t;
    int have_termios = 0;

    if (stdin_is_tty() && tcgetattr(STDIN_FILENO, &old_t) == 0) {
        new_t = old_t;
        new_t.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_t) == 0) have_termios = 1;
    }

    size_t cap = 256;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        if (have_termios) tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_t);
        return NULL;
    }
    size_t len = 0;
    int c;
    while ((c = fgetc(stdin)) != EOF && c != '\n') {
        if (len + 1 >= cap) {
            size_t new_cap = cap * 2;
            char *nb = (char *)realloc(buf, new_cap);
            if (!nb) { gv_wipe(buf, cap); free(buf);
                       if (have_termios) tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_t);
                       return NULL; }
            buf = nb; cap = new_cap;
        }
        buf[len++] = (char)c;
    }
    buf[len] = '\0';

    if (have_termios) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_t);
        fputc('\n', stderr);  /* enter tidak ter-echo, tambahkan newline manual */
    }
    return buf;
}

char *gv_read_line(const char *prompt) {
    if (prompt) { fputs(prompt, stderr); fflush(stderr); }
    size_t cap = 256;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    size_t len = 0;
    int c;
    while ((c = fgetc(stdin)) != EOF && c != '\n') {
        if (len + 1 >= cap) {
            size_t new_cap = cap * 2;
            char *nb = (char *)realloc(buf, new_cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb; cap = new_cap;
        }
        buf[len++] = (char)c;
    }
    buf[len] = '\0';
    return buf;
}

void gv_print_banner(void) {
    int c = stderr_is_tty();
    if (c) fputs("\033[35m\033[1m", stderr);
    fputs("\xE2\x95\x94\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x97\n", stderr);
    fputs("\xE2\x95\x91\x20\x20\x43\x20\x52\x20\x59\x20\x50\x20\x54\x20\x4F\x20\x2F\x20\x2F\x20\x47\x20\x4F\x20\x44\x20\x20\x20\x56\x20\x41\x20\x55\x20\x4C\x20\x54\x20\x20\x20\xE2\x80\x94\x20\x20\x20\x43\x20\x20\x20\x45\x20\x44\x20\x49\x20\x54\x20\x49\x20\x4F\x20\x4E\x20\x20\xE2\x95\x91\n", stderr);
    fputs("\xE2\x95\x91\x20\x20\x20\x20\x41\x45\x53\x2D\x32\x35\x36\x2D\x47\x43\x4D\x20\xC2\xB7\x20\x41\x72\x67\x6F\x6E\x32\x69\x64\x2F\x50\x42\x4B\x44\x46\x32\x20\xC2\xB7\x20\x48\x4B\x44\x46\x20\xC2\xB7\x20\x48\x4D\x41\x43\x2D\x53\x48\x41\x35\x31\x32\x20\xC3\x97\x32\x20\x20\x20\x20\xE2\x95\x91\n", stderr);
    fputs("\xE2\x95\x9A\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x9D\n", stderr);
    if (c) fputs("\033[0m", stderr);
    fflush(stderr);
}

static void print_tagged(const char *tag, const char *color, const char *fmt, va_list ap) {
    int c = stderr_is_tty();
    if (c) fprintf(stderr, "%s%s\033[0m ", color, tag);
    else    fprintf(stderr, "%s ", tag);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
}

void gv_info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    print_tagged("[INFO]", "\033[36m", fmt, ap);
    va_end(ap);
}
void gv_ok(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    print_tagged("[ OK ]", "\033[32m", fmt, ap);
    va_end(ap);
}
void gv_warn(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    print_tagged("[WARN]", "\033[33m", fmt, ap);
    va_end(ap);
}
void gv_error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    print_tagged("[FAIL]", "\033[31m", fmt, ap);
    va_end(ap);
}
