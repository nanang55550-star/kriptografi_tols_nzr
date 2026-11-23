#ifndef GODVAULT_RATELIMIT_H
#define GODVAULT_RATELIMIT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define GV_RATELIMIT_MAX_ATTEMPTS   5
#define GV_RATELIMIT_COOLDOWN_BASE  30   /* detik */

typedef struct {
    char path[4096];
} gv_ratelimiter_t;

/* path custom (mis. utk unit test, supaya tidak menyentuh $HOME asli). */
void gv_ratelimiter_init(gv_ratelimiter_t *rl, const char *path);
/* pakai $HOME/.godvaultc_rate_limit sbg default. */
void gv_ratelimiter_init_default(gv_ratelimiter_t *rl);

/* true = boleh coba. Kalau false, *wait_seconds_out diisi sisa cooldown. */
bool gv_ratelimiter_check(const gv_ratelimiter_t *rl, int64_t *wait_seconds_out);

void gv_ratelimiter_record(const gv_ratelimiter_t *rl, bool success);

void gv_ratelimiter_status(const gv_ratelimiter_t *rl, char *out, size_t out_cap);

#endif /* GODVAULT_RATELIMIT_H */
