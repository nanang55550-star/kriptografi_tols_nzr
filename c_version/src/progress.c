#include "progress.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void gv_progress_printer_init(gv_progress_printer_t *p) {
    memset(p, 0, sizeof(*p));
    p->is_tty = isatty(fileno(stderr));  /* progress -> stderr, bukan stdout (lihat term.c) */
}

static const char *stage_label(const char *stage) {
    if (strcmp(stage, "read") == 0)    return "Membaca & mengenkripsi";
    if (strcmp(stage, "verify") == 0)  return "Memverifikasi integritas";
    if (strcmp(stage, "decrypt") == 0) return "Mendekripsi & menulis";
    return stage;
}

void gv_progress_printer_cb(const char *stage, uint64_t done, uint64_t total, void *ctx) {
    gv_progress_printer_t *p = (gv_progress_printer_t *)ctx;
    if (!p || !p->is_tty || total == 0) return;

    double now = now_seconds();

    if (strcmp(p->stage, stage) != 0) {
        if (p->stage[0] != '\0') fputc('\n', stderr);
        strncpy(p->stage, stage, sizeof(p->stage) - 1);
        p->stage[sizeof(p->stage) - 1] = '\0';
        p->start_time = now;
        p->last_print = 0.0;
    }

    int finished = (done >= total);
    if (!finished && (now - p->last_print) < 0.08) return;
    p->last_print = now;

    double frac = (double)done / (double)total;
    if (frac > 1.0) frac = 1.0;
    int width = 28;
    int filled = (int)(width * frac);

    char bar[3 * 28 + 1]; /* blok unicode "█"/"░" tiap 3 byte UTF-8 */
    int bo = 0;
    for (int i = 0; i < width; i++) {
        const char *sym = (i < filled) ? "\xE2\x96\x88" : "\xE2\x96\x91"; /* █ / ░ */
        memcpy(bar + bo, sym, 3);
        bo += 3;
    }
    bar[bo] = '\0';

    double elapsed = now - p->start_time;
    if (elapsed < 1e-6) elapsed = 1e-6;
    double speed = (double)done / elapsed;
    double eta = speed > 0 ? ((double)total - (double)done) / speed : 0;

    char done_s[32], total_s[32], speed_s[32];
    gv_format_bytes((double)done, done_s, sizeof(done_s));
    gv_format_bytes((double)total, total_s, sizeof(total_s));
    gv_format_bytes(speed, speed_s, sizeof(speed_s));

    fprintf(stderr, "\r\033[36m%s\033[0m [\033[32m%s\033[0m] %5.1f%%  %s/%s  %s/s  ETA %ds   ",
            stage_label(stage), bar, frac * 100.0, done_s, total_s, speed_s, (int)eta);
    fflush(stderr);

    if (finished) {
        fputc('\n', stderr);
        fflush(stderr);
    }
}
