/*
 * cli.c - PQ-Zip command-line interface (for scripting, servers, headless).
 *
 *   pqzip c  -o out.pqz [opts] FILE|DIR...     compress
 *   pqzip x  in.pqz [DEST_DIR] [opts]          extract
 *   pqzip --help | --version
 */
#include "pqzip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#ifndef PQZIP_VERSION
#define PQZIP_VERSION "1.0.6"
#endif

static int g_quiet = 0;

static void usage(FILE *o) {
    fprintf(o,
"PQ-Zip " PQZIP_VERSION " - post-quantum compressing archiver.\n"
"\n"
"Usage:\n"
"  pqzip c -o ARCHIVE.pqz [options] FILE|DIR...   compress & encrypt\n"
"  pqzip x ARCHIVE.pqz [DEST_DIR] [options]       decrypt & extract\n"
"  pqzip --help | --version\n"
"\n"
"Options:\n"
"  -o FILE         output .pqz file (compress; required)\n"
"  -d DIR          destination directory (extract; default '.')\n"
"  -p PASSWORD     password (else $PQZIP_PASSWORD, else prompt)\n"
"  --cipher NAME   aes | xchacha | chacha            (default aes)\n"
"  --kdf LEVEL     basic | medium | strong           (default medium)\n"
"  --level N       zlib compression level 0-9        (default 6)\n"
"  --no-hybrid     disable Kyber-1024 + X448 hybrid KEM (on by default)\n"
"  -q, --quiet     suppress progress output\n"
"\n"
"With no arguments PQ-Zip launches its graphical interface.\n");
}

/* Read a password from the controlling terminal with echo disabled. */
static int prompt_password(char *buf, size_t buflen, int confirm) {
    struct termios old, noecho;
    int have_tty = (tcgetattr(STDIN_FILENO, &old) == 0);
    if (have_tty) {
        noecho = old;
        noecho.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho);
    }
    int rc = -1;
    fprintf(stderr, "Password: ");
    fflush(stderr);
    if (fgets(buf, (int)buflen, stdin)) {
        buf[strcspn(buf, "\n")] = '\0';
        fprintf(stderr, "\n");
        if (confirm) {
            char again[1024];
            fprintf(stderr, "Confirm password: ");
            fflush(stderr);
            if (fgets(again, sizeof(again), stdin)) {
                again[strcspn(again, "\n")] = '\0';
                fprintf(stderr, "\n");
                if (strcmp(buf, again) == 0) rc = 0;
                else fprintf(stderr, "pqzip: passwords do not match.\n");
            }
            volatile char *z = again; for (size_t i = 0; i < sizeof(again); i++) z[i] = 0;
        } else {
            rc = 0;
        }
    }
    if (have_tty) tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    return rc;
}

static int resolve_password(const char *opt, char *buf, size_t buflen, int confirm) {
    if (opt) { snprintf(buf, buflen, "%s", opt); return 0; }
    const char *env = getenv("PQZIP_PASSWORD");
    if (env && *env) { snprintf(buf, buflen, "%s", env); return 0; }
    return prompt_password(buf, buflen, confirm);
}

static int parse_cipher(const char *s, cipher_id_t *out) {
    if (!strcmp(s, "aes"))     { *out = CIPHER_AES_256_GCM; return 0; }
    if (!strcmp(s, "xchacha")) { *out = CIPHER_XCHACHA20_POLY1305; return 0; }
    if (!strcmp(s, "chacha"))  { *out = CIPHER_CHACHA20_POLY1305_IETF; return 0; }
    return -1;
}
static int parse_kdf(const char *s, kdf_level_t *out) {
    if (!strcmp(s, "basic"))  { *out = KDF_BASIC; return 0; }
    if (!strcmp(s, "medium")) { *out = KDF_MEDIUM; return 0; }
    if (!strcmp(s, "strong")) { *out = KDF_STRONG; return 0; }
    return -1;
}

static int cli_progress(uint64_t done, uint64_t total, void *user) {
    (void)user;
    if (g_quiet) return 0;
    if (total)
        fprintf(stderr, "\r  %3.0f%%  ", 100.0 * (double)done / (double)total);
    else
        fprintf(stderr, "\r  %llu bytes  ", (unsigned long long)done);
    fflush(stderr);
    return 0;
}

int cli_main(int argc, char **argv) {
    const char *cmd = argv[1];
    if (!strcmp(cmd, "--help") || !strcmp(cmd, "-h")) { usage(stdout); return 0; }
    if (!strcmp(cmd, "--version") || !strcmp(cmd, "-v")) {
        printf("pqzip %s\n", PQZIP_VERSION); return 0;
    }

    int compress;
    if (!strcmp(cmd, "c") || !strcmp(cmd, "compress")) compress = 1;
    else if (!strcmp(cmd, "x") || !strcmp(cmd, "extract")) compress = 0;
    else { fprintf(stderr, "pqzip: unknown command '%s'\n\n", cmd); usage(stderr); return 2; }

    const char *out = NULL, *dest = NULL, *passopt = NULL;
    cipher_id_t cipher = CIPHER_AES_256_GCM;
    kdf_level_t kdf = KDF_MEDIUM;
    int hybrid = 1, zlevel = 6;
    const char *positionals[4096];
    int n_pos = 0;

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-o") && i + 1 < argc)            out = argv[++i];
        else if (!strcmp(a, "-d") && i + 1 < argc)       dest = argv[++i];
        else if (!strcmp(a, "-p") && i + 1 < argc)       passopt = argv[++i];
        else if (!strcmp(a, "--cipher") && i + 1 < argc) {
            if (parse_cipher(argv[++i], &cipher)) { fprintf(stderr, "pqzip: bad --cipher\n"); return 2; }
        } else if (!strcmp(a, "--kdf") && i + 1 < argc) {
            if (parse_kdf(argv[++i], &kdf)) { fprintf(stderr, "pqzip: bad --kdf\n"); return 2; }
        } else if (!strcmp(a, "--level") && i + 1 < argc) {
            zlevel = atoi(argv[++i]);
            if (zlevel < 0 || zlevel > 9) { fprintf(stderr, "pqzip: --level must be 0-9\n"); return 2; }
        } else if (!strcmp(a, "--no-hybrid"))            hybrid = 0;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) g_quiet = 1;
        else if (a[0] == '-' && a[1]) { fprintf(stderr, "pqzip: unknown option '%s'\n", a); return 2; }
        else { if (n_pos < (int)(sizeof(positionals)/sizeof(positionals[0]))) positionals[n_pos++] = a; }
    }

    char password[4096];
    char err[256] = {0};
    int rc;

    if (compress) {
        if (!out) { fprintf(stderr, "pqzip: -o ARCHIVE.pqz is required for compress\n"); return 2; }
        if (n_pos == 0) { fprintf(stderr, "pqzip: no input files or directories given\n"); return 2; }
        if (resolve_password(passopt, password, sizeof(password), 1) != 0) return 1;
        rc = pqz_create(positionals, n_pos, out, password, cipher, kdf, hybrid,
                        zlevel, cli_progress, NULL, err, sizeof(err));
    } else {
        if (n_pos < 1) { fprintf(stderr, "pqzip: extract needs ARCHIVE.pqz\n"); return 2; }
        const char *in = positionals[0];
        const char *d = dest ? dest : (n_pos >= 2 ? positionals[1] : ".");
        if (resolve_password(passopt, password, sizeof(password), 0) != 0) return 1;
        rc = pqz_extract(in, d, password, cli_progress, NULL, err, sizeof(err));
    }

    /* Scrub the password copy. */
    volatile char *z = password; for (size_t i = 0; i < sizeof(password); i++) z[i] = 0;

    if (!g_quiet) fprintf(stderr, "\n");
    if (rc != 0) { fprintf(stderr, "pqzip: %s\n", err[0] ? err : "operation failed"); return 1; }
    if (!g_quiet) fprintf(stderr, "%s\n", compress ? "Done." : "Extracted.");
    return 0;
}
