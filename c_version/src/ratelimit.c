#include "ratelimit.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <unistd.h>
#endif

#define RL_MAGIC "GVRL"
#define RL_RECORD_SIZE (4 + 4 + 8 + 8)  /* magic + attempts + last_attempt + cooldown_until */

typedef struct {
    uint32_t attempts;
    int64_t  last_attempt;
    int64_t  cooldown_until;
} rl_state_t;

void gv_ratelimiter_init(gv_ratelimiter_t *rl, const char *path) {
    strncpy(rl->path, path, sizeof(rl->path) - 1);
    rl->path[sizeof(rl->path) - 1] = '\0';
}

void gv_ratelimiter_init_default(gv_ratelimiter_t *rl) {
    const char *home = getenv("HOME");
    if (!home) home = ".";
    snprintf(rl->path, sizeof(rl->path), "%s/.godvaultc_rate_limit", home);
}

static void rl_load(const gv_ratelimiter_t *rl, rl_state_t *st) {
    memset(st, 0, sizeof(*st));
    FILE *f = fopen(rl->path, "rb");
    if (!f) return;

    uint8_t buf[RL_RECORD_SIZE];
    size_t got = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (got != sizeof(buf)) return;              /* file rusak/beda versi -> anggap state fresh */
    if (memcmp(buf, RL_MAGIC, 4) != 0) return;

    st->attempts = gv_get_u32(buf + 4);
    st->last_attempt = (int64_t)gv_get_u64(buf + 8);
    st->cooldown_until = (int64_t)gv_get_u64(buf + 16);
}

static void rl_save(const gv_ratelimiter_t *rl, const rl_state_t *st) {
    uint8_t buf[RL_RECORD_SIZE];
    memcpy(buf, RL_MAGIC, 4);
    gv_put_u32(buf + 4, st->attempts);
    gv_put_u64(buf + 8, (uint64_t)st->last_attempt);
    gv_put_u64(buf + 16, (uint64_t)st->cooldown_until);

    FILE *f = fopen(rl->path, "wb");
    if (!f) return;
    fwrite(buf, 1, sizeof(buf), f);
    fclose(f);
#ifndef _WIN32
    chmod(rl->path, 0600);
#endif
}

bool gv_ratelimiter_check(const gv_ratelimiter_t *rl, int64_t *wait_seconds_out) {
    rl_state_t st;
    rl_load(rl, &st);
    int64_t now = gv_now_unix();

    if (now < st.cooldown_until) {
        if (wait_seconds_out) *wait_seconds_out = st.cooldown_until - now;
        return false;
    }
    if (wait_seconds_out) *wait_seconds_out = 0;
    return true;
}

void gv_ratelimiter_record(const gv_ratelimiter_t *rl, bool success) {
    rl_state_t st;
    rl_load(rl, &st);
    int64_t now = gv_now_unix();

    if (success) {
        st.attempts = 0;
        st.cooldown_until = 0;
    } else {
        if (now - st.last_attempt > 3600) st.attempts = 0;  /* reset kalau sudah lama tak ada percobaan */
        st.attempts += 1;
        st.last_attempt = now;
        if (st.attempts >= GV_RATELIMIT_MAX_ATTEMPTS) {
            uint32_t excess = st.attempts - GV_RATELIMIT_MAX_ATTEMPTS;
            int64_t multiplier = ((int64_t)1) << (excess < 20 ? excess : 20); /* cegah overflow shift */
            st.cooldown_until = now + (GV_RATELIMIT_COOLDOWN_BASE * multiplier);
        }
    }
    rl_save(rl, &st);
}

void gv_ratelimiter_status(const gv_ratelimiter_t *rl, char *out, size_t out_cap) {
    rl_state_t st;
    rl_load(rl, &st);
    int64_t now = gv_now_unix();
    if (now < st.cooldown_until) {
        snprintf(out, out_cap, "Rate limit aktif -- tunggu %lld detik.", (long long)(st.cooldown_until - now));
    } else {
        snprintf(out, out_cap, "Attempts: %u/%d", st.attempts, GV_RATELIMIT_MAX_ATTEMPTS);
    }
}
