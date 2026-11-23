/* ==========================================================================
 * main.c — CRYPTO//GOD VAULT (C EDITION) — CLI & menu interaktif
 * ========================================================================== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "vault_format.h"
#include "vault_api.h"
#include "term.h"
#include "password.h"
#include "ratelimit.h"
#include "progress.h"
#include "base64.h"
#include "util.h"
#include "kdf.h"

#define GV_OUT_EXT ".gvc"

/* ==========================================================================
 * Helper umum
 * ========================================================================== */

static void report_status(gv_status_t st) {
    if (st != GV_OK) gv_error("%s", gv_status_str(st));
}

static char *ask_password_confirmed(void) {
    for (;;) {
        char *pwd1 = gv_read_password("Buat password: ");
        if (!pwd1) return NULL;
        if (pwd1[0] == '\0') {
            gv_error("Password tidak boleh kosong.\n");
            gv_wipe(pwd1, strlen(pwd1)); free(pwd1);
            continue;
        }

        char reason[160];
        bool ok = gv_password_validate(pwd1, reason, sizeof(reason));
        if (ok) {
            gv_ok("%s", reason);
        } else {
            gv_warn("%s", reason);
            char *ans = gv_read_line("Tetap pakai password ini? (y/N): ");
            int use_anyway = ans && (ans[0] == 'y' || ans[0] == 'Y');
            free(ans);
            if (!use_anyway) {
                gv_wipe(pwd1, strlen(pwd1)); free(pwd1);
                continue;
            }
        }

        char *pwd2 = gv_read_password("Ulangi password: ");
        if (!pwd2) { gv_wipe(pwd1, strlen(pwd1)); free(pwd1); return NULL; }
        int same = (strcmp(pwd1, pwd2) == 0);
        gv_wipe(pwd2, strlen(pwd2)); free(pwd2);
        if (!same) {
            gv_error("Password tidak sama, coba lagi.\n");
            gv_wipe(pwd1, strlen(pwd1)); free(pwd1);
            continue;
        }
        return pwd1;
    }
}

static const char *kdf_name(uint8_t kdf_id) {
    return kdf_id == GV_KDF_ARGON2ID ? "Argon2id" : "PBKDF2-SHA512 (fallback)";
}

/* ==========================================================================
 * Menu interaktif
 * ========================================================================== */

static void menu_encrypt_text(void) {
    char *pesan = gv_read_line("Masukkan pesan rahasia Anda: ");
    if (!pesan) return;
    char *pwd = ask_password_confirmed();
    if (!pwd) { free(pesan); return; }

    uint8_t *blob = NULL; size_t blob_len = 0;
    gv_status_t st = gv_encrypt_bytes((const uint8_t *)pesan, strlen(pesan),
                                       pwd, strlen(pwd), 1, gv_kdf_preferred(), &blob, &blob_len);
    if (st == GV_OK) {
        char *b64 = gv_base64_encode(blob, blob_len);
        printf("\n\033[1m--- HASIL ENKRIPSI ---\033[0m\n%s\n", b64 ? b64 : "(gagal encode)");
        free(b64);
        free(blob);
    } else {
        report_status(st);
    }
    gv_wipe(pesan, strlen(pesan)); free(pesan);
    gv_wipe(pwd, strlen(pwd)); free(pwd);
}

static void menu_decrypt_text(void) {
    gv_ratelimiter_t rl; gv_ratelimiter_init_default(&rl);
    int64_t wait;
    if (!gv_ratelimiter_check(&rl, &wait)) {
        gv_error("Rate limit aktif. Tunggu %lld detik sebelum mencoba lagi.", (long long)wait);
        return;
    }

    char *b64 = gv_read_line("Tempel (paste) vault terenkripsi: ");
    if (!b64) return;
    char *pwd = gv_read_password("Masukkan password: ");
    if (!pwd) { free(b64); return; }

    size_t blob_len;
    uint8_t *blob = gv_base64_decode(b64, &blob_len);
    printf("\n\033[1m--- HASIL TERJEMAHAN ---\033[0m\n");
    if (!blob) {
        gv_error("%s", gv_status_str(GV_ERR_FORMAT));
        gv_ratelimiter_record(&rl, false);
    } else {
        uint8_t *out = NULL; size_t out_len = 0;
        gv_status_t st = gv_decrypt_bytes(blob, blob_len, pwd, strlen(pwd), &out, &out_len);
        if (st == GV_OK) {
            fwrite(out, 1, out_len, stdout);
            printf("\n");
            gv_ratelimiter_record(&rl, true);
            gv_wipe(out, out_len);
        } else {
            report_status(st);
            gv_ratelimiter_record(&rl, false);
        }
        free(out);
        free(blob);
    }

    gv_wipe(b64, strlen(b64)); free(b64);
    gv_wipe(pwd, strlen(pwd)); free(pwd);
}

static void menu_encrypt_file(void) {
    char *in_path = gv_read_line("Path file yang mau dienkripsi: ");
    if (!in_path) return;
    FILE *test = fopen(in_path, "rb");
    if (!test) {
        gv_error("File tidak ditemukan.");
        free(in_path);
        return;
    }
    fclose(test);

    char prompt[4200];
    snprintf(prompt, sizeof(prompt), "Path output [%s%s]: ", in_path, GV_OUT_EXT);
    char *out_in = gv_read_line(prompt);
    char out_path[4200];
    if (out_in && out_in[0]) snprintf(out_path, sizeof(out_path), "%s", out_in);
    else snprintf(out_path, sizeof(out_path), "%s%s", in_path, GV_OUT_EXT);
    free(out_in);

    char *pwd = ask_password_confirmed();
    if (!pwd) { free(in_path); return; }

    char *comp_ans = gv_read_line("Kompresi sebelum enkripsi? (Y/n): ");
    int compress = !(comp_ans && (comp_ans[0] == 'n' || comp_ans[0] == 'N'));
    free(comp_ans);

    gv_progress_printer_t prog; gv_progress_printer_init(&prog);
    gv_status_t st = gv_encrypt_file(in_path, out_path, pwd, strlen(pwd),
                                      compress, gv_kdf_preferred(), GV_DEFAULT_CHUNK_SIZE,
                                      gv_progress_printer_cb, &prog);
    if (st == GV_OK) gv_ok("File terenkripsi disimpan di: %s", out_path);
    else report_status(st);

    free(in_path);
    gv_wipe(pwd, strlen(pwd)); free(pwd);
}

static void menu_decrypt_file(void) {
    gv_ratelimiter_t rl; gv_ratelimiter_init_default(&rl);
    int64_t wait;
    if (!gv_ratelimiter_check(&rl, &wait)) {
        gv_error("Rate limit aktif. Tunggu %lld detik sebelum mencoba lagi.", (long long)wait);
        return;
    }

    char *in_path = gv_read_line("Path file vault (" GV_OUT_EXT "): ");
    if (!in_path) return;
    FILE *test = fopen(in_path, "rb");
    if (!test) {
        gv_error("File tidak ditemukan.");
        free(in_path);
        return;
    }
    fclose(test);

    char default_out[4200];
    size_t plen = strlen(in_path);
    size_t extlen = strlen(GV_OUT_EXT);
    if (plen > extlen && strcmp(in_path + plen - extlen, GV_OUT_EXT) == 0) {
        snprintf(default_out, sizeof(default_out), "%.*s", (int)(plen - extlen), in_path);
    } else {
        snprintf(default_out, sizeof(default_out), "%s.dec", in_path);
    }

    char prompt[4300];
    snprintf(prompt, sizeof(prompt), "Path output [%s]: ", default_out);
    char *out_in = gv_read_line(prompt);
    const char *out_path = (out_in && out_in[0]) ? out_in : default_out;

    char *pwd = gv_read_password("Masukkan password: ");
    if (!pwd) { free(in_path); free(out_in); return; }

    gv_progress_printer_t prog; gv_progress_printer_init(&prog);
    gv_header_t meta;
    gv_status_t st = gv_decrypt_file(in_path, out_path, pwd, strlen(pwd), &meta,
                                      gv_progress_printer_cb, &prog);
    if (st == GV_OK) {
        gv_ok("File hasil dekripsi disimpan di: %s", out_path);
        gv_ratelimiter_record(&rl, true);
    } else {
        report_status(st);
        gv_ratelimiter_record(&rl, false);
    }

    free(in_path); free(out_in);
    gv_wipe(pwd, strlen(pwd)); free(pwd);
}

static void menu_generate_password(void) {
    char *raw = gv_read_line("Panjang password [24]: ");
    long length = 24;
    if (raw && raw[0]) {
        char *end;
        long v = strtol(raw, &end, 10);
        if (*end == '\0' && v > 0 && v < 1000) length = v;
    }
    free(raw);

    char *pwd = (char *)malloc((size_t)length + 1);
    if (!pwd || !gv_password_generate(pwd, (size_t)length)) {
        gv_error("Gagal membuat password acak.");
        free(pwd);
        return;
    }
    double bits = gv_password_entropy(pwd);
    gv_info("Estimasi entropy: ~%.0f bit", bits);
    gv_warn("SIMPAN password ini SEKARANG. Tidak akan ditampilkan lagi.");
    printf("\033[1m\033[32m%s\033[0m\n", pwd);
    gv_wipe(pwd, (size_t)length); free(pwd);
}

static void menu_status(void) {
    gv_ratelimiter_t rl; gv_ratelimiter_init_default(&rl);
    char buf[128];
    gv_ratelimiter_status(&rl, buf, sizeof(buf));
    gv_info("%s", buf);
    gv_info("KDF aktif: %s", kdf_name(gv_kdf_preferred()));
}

static void interactive_menu(void) {
    gv_print_banner();
    gv_info("KDF aktif: %s", kdf_name(gv_kdf_preferred()));
    if (!gv_argon2_available()) {
        gv_warn("Build ini TANPA dukungan Argon2id -- cuma PBKDF2 (kompilasi ulang dgn libargon2 utk KDF terkuat).");
    }

    for (;;) {
        printf("\n\033[36m (m)\033[0m Enkripsi teks\n");
        printf("\033[36m (j)\033[0m Dekripsi teks\n");
        printf("\033[36m (f)\033[0m Enkripsi file\n");
        printf("\033[36m (d)\033[0m Dekripsi file\n");
        printf("\033[36m (g)\033[0m Generate password acak\n");
        printf("\033[36m (s)\033[0m Status rate-limiter\n");
        printf("\033[36m (q)\033[0m Keluar\n");

        char *choice = gv_read_line("\nPilih: ");
        if (!choice) break;
        printf("\n");

        char c = choice[0];
        free(choice);

        if (c == 'm') menu_encrypt_text();
        else if (c == 'j') menu_decrypt_text();
        else if (c == 'f') menu_encrypt_file();
        else if (c == 'd') menu_decrypt_file();
        else if (c == 'g') menu_generate_password();
        else if (c == 's') menu_status();
        else if (c == 'q') { printf("Sampai jumpa.\n"); break; }
        else gv_warn("Pilihan tidak valid.");
    }
}

/* ==========================================================================
 * CLI (non-interaktif)
 * ========================================================================== */

static void print_usage(void) {
    printf(
        "CRYPTO//GOD VAULT (C edition) -- AES-256-GCM + Argon2id/PBKDF2 + HKDF + HMAC-SHA512 ganda\n\n"
        "Pemakaian:\n"
        "  godvaultc                                   menu interaktif\n"
        "  godvaultc enc -m \"teks\" [--force]\n"
        "  godvaultc enc -i FILE [-o OUT] [--no-compress] [--force] [--kdf argon2id|pbkdf2]\n"
        "  godvaultc dec -m \"teks-base64\"\n"
        "  godvaultc dec -i FILE [-o OUT]\n"
        "  godvaultc genpass [-l N]\n"
        "  godvaultc status\n"
    );
}

static int cli_enc(int argc, char **argv) {
    const char *message = NULL, *input = NULL, *output = NULL, *kdf_opt = NULL;
    int no_compress = 0, force = 0;

    for (int i = 0; i < argc; i++) {
        if ((strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--message") == 0) && i + 1 < argc) message = argv[++i];
        else if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) && i + 1 < argc) input = argv[++i];
        else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) output = argv[++i];
        else if (strcmp(argv[i], "--no-compress") == 0) no_compress = 1;
        else if (strcmp(argv[i], "--force") == 0) force = 1;
        else if (strcmp(argv[i], "--kdf") == 0 && i + 1 < argc) kdf_opt = argv[++i];
        else { gv_error("Argumen tidak dikenal: %s", argv[i]); return 1; }
    }
    if ((!message && !input) || (message && input)) {
        gv_error("Isi salah satu: -m TEKS  ATAU  -i FILE (tidak keduanya).");
        return 1;
    }

    uint8_t kdf_id = gv_kdf_preferred();
    if (kdf_opt) {
        if (strcmp(kdf_opt, "argon2id") == 0) kdf_id = GV_KDF_ARGON2ID;
        else if (strcmp(kdf_opt, "pbkdf2") == 0) kdf_id = GV_KDF_PBKDF2;
        else { gv_error("--kdf harus 'argon2id' atau 'pbkdf2'"); return 1; }
        if (kdf_id == GV_KDF_ARGON2ID && !gv_argon2_available()) {
            gv_error("Argon2id diminta tapi build ini tidak mendukungnya.");
            return 1;
        }
    }

    char *pwd = gv_read_password("Password: ");
    if (!pwd) return 1;

    if (!force) {
        char reason[160];
        if (!gv_password_validate(pwd, reason, sizeof(reason))) {
            gv_error("Password lemah: %s (pakai --force utk lewati)", reason);
            gv_wipe(pwd, strlen(pwd)); free(pwd);
            return 1;
        }
    }

    int rc = 0;
    if (message) {
        uint8_t *blob = NULL; size_t blob_len = 0;
        gv_status_t st = gv_encrypt_bytes((const uint8_t *)message, strlen(message),
                                           pwd, strlen(pwd), !no_compress, kdf_id, &blob, &blob_len);
        if (st == GV_OK) {
            char *b64 = gv_base64_encode(blob, blob_len);
            printf("%s\n", b64 ? b64 : "");
            free(b64); free(blob);
        } else { report_status(st); rc = 1; }
    } else {
        char out_buf[4200];
        if (!output) { snprintf(out_buf, sizeof(out_buf), "%s%s", input, GV_OUT_EXT); output = out_buf; }
        gv_status_t st = gv_encrypt_file(input, output, pwd, strlen(pwd),
                                          !no_compress, kdf_id, GV_DEFAULT_CHUNK_SIZE, NULL, NULL);
        if (st == GV_OK) gv_ok("Tersimpan di %s", output);
        else { report_status(st); rc = 1; }
    }

    gv_wipe(pwd, strlen(pwd)); free(pwd);
    return rc;
}

static int cli_dec(int argc, char **argv) {
    const char *message = NULL, *input = NULL, *output = NULL;
    for (int i = 0; i < argc; i++) {
        if ((strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--message") == 0) && i + 1 < argc) message = argv[++i];
        else if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) && i + 1 < argc) input = argv[++i];
        else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) output = argv[++i];
        else { gv_error("Argumen tidak dikenal: %s", argv[i]); return 1; }
    }
    if ((!message && !input) || (message && input)) {
        gv_error("Isi salah satu: -m TEKS  ATAU  -i FILE (tidak keduanya).");
        return 1;
    }

    gv_ratelimiter_t rl; gv_ratelimiter_init_default(&rl);
    int64_t wait;
    if (!gv_ratelimiter_check(&rl, &wait)) {
        gv_error("Rate limit aktif. Tunggu %lld detik.", (long long)wait);
        return 1;
    }

    char *pwd = gv_read_password("Password: ");
    if (!pwd) return 1;

    int rc = 0;
    if (message) {
        size_t blob_len;
        uint8_t *blob = gv_base64_decode(message, &blob_len);
        if (!blob) {
            gv_error("%s", gv_status_str(GV_ERR_FORMAT));
            gv_ratelimiter_record(&rl, false);
            rc = 1;
        } else {
            uint8_t *out = NULL; size_t out_len = 0;
            gv_status_t st = gv_decrypt_bytes(blob, blob_len, pwd, strlen(pwd), &out, &out_len);
            if (st == GV_OK) {
                fwrite(out, 1, out_len, stdout);
                printf("\n");
                gv_ratelimiter_record(&rl, true);
                gv_wipe(out, out_len);
            } else {
                report_status(st);
                gv_ratelimiter_record(&rl, false);
                rc = 1;
            }
            free(out);
            free(blob);
        }
    } else {
        char out_buf[4200];
        if (!output) {
            size_t plen = strlen(input), extlen = strlen(GV_OUT_EXT);
            if (plen > extlen && strcmp(input + plen - extlen, GV_OUT_EXT) == 0)
                snprintf(out_buf, sizeof(out_buf), "%.*s", (int)(plen - extlen), input);
            else
                snprintf(out_buf, sizeof(out_buf), "%s.dec", input);
            output = out_buf;
        }
        gv_status_t st = gv_decrypt_file(input, output, pwd, strlen(pwd), NULL, NULL, NULL);
        if (st == GV_OK) { gv_ok("Tersimpan di %s", output); gv_ratelimiter_record(&rl, true); }
        else { report_status(st); gv_ratelimiter_record(&rl, false); rc = 1; }
    }

    gv_wipe(pwd, strlen(pwd)); free(pwd);
    return rc;
}

static int cli_genpass(int argc, char **argv) {
    long length = 24;
    for (int i = 0; i < argc; i++) {
        if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--length") == 0) && i + 1 < argc) {
            length = strtol(argv[++i], NULL, 10);
        }
    }
    if (length <= 0 || length > 1000) length = 24;

    char *pwd = (char *)malloc((size_t)length + 1);
    if (!pwd || !gv_password_generate(pwd, (size_t)length)) {
        gv_error("Gagal membuat password.");
        free(pwd);
        return 1;
    }
    gv_info("Entropy: ~%.0f bit", gv_password_entropy(pwd));
    printf("%s\n", pwd);
    gv_wipe(pwd, (size_t)length); free(pwd);
    return 0;
}

static int cli_status(void) {
    gv_ratelimiter_t rl; gv_ratelimiter_init_default(&rl);
    char buf[128];
    gv_ratelimiter_status(&rl, buf, sizeof(buf));
    gv_info("%s", buf);
    gv_info("KDF aktif: %s", kdf_name(gv_kdf_preferred()));
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        interactive_menu();
        return 0;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "enc") == 0) return cli_enc(argc - 2, argv + 2);
    if (strcmp(cmd, "dec") == 0) return cli_dec(argc - 2, argv + 2);
    if (strcmp(cmd, "genpass") == 0) return cli_genpass(argc - 2, argv + 2);
    if (strcmp(cmd, "status") == 0) return cli_status();
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) { print_usage(); return 0; }

    gv_error("Subperintah tidak dikenal: %s", cmd);
    print_usage();
    return 1;
}
