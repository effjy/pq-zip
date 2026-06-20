/*
 * pqzip.c - PQ-Zip high-level pipeline (see pqzip.h).
 */
#include "pqzip.h"
#include "archive.h"
#include "compress.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

static void seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg);
}

/* Open an anonymous temp file (created then immediately unlinked) for staging
 * the intermediate archive/compressed streams. Honors $TMPDIR, else /tmp. */
static FILE *open_tmp(char *err, size_t errlen) {
    const char *dir = getenv("TMPDIR");
    if (!dir || !*dir) dir = "/tmp";
    char tmpl[4096];
    if (snprintf(tmpl, sizeof(tmpl), "%s/pqzip-XXXXXX", dir) >= (int)sizeof(tmpl)) {
        seterr(err, errlen, "Temp path too long."); return NULL;
    }
    int fd = mkstemp(tmpl);
    if (fd < 0) { seterr(err, errlen, "Cannot create temp file."); return NULL; }
    unlink(tmpl);   /* anonymous from here on; removed when the fd closes */
    FILE *f = fdopen(fd, "w+b");
    if (!f) { close(fd); seterr(err, errlen, "Cannot open temp file."); return NULL; }
    return f;
}

static int same_file(const char *a, const char *b) {
    struct stat sa, sb;
    if (stat(a, &sa) != 0 || stat(b, &sb) != 0) return 0;
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

static void fsync_parent_dir(const char *path) {
    char dir[4096];
    const char *slash = strrchr(path, '/');
    if (slash == path) { dir[0] = '/'; dir[1] = '\0'; }
    else if (slash) {
        size_t n = (size_t)(slash - path);
        if (n >= sizeof(dir)) return;
        memcpy(dir, path, n); dir[n] = '\0';
    } else { dir[0] = '.'; dir[1] = '\0'; }
    int fd = open(dir, O_RDONLY
#ifdef O_DIRECTORY
                  | O_DIRECTORY
#endif
                  );
    if (fd < 0) return;
    fsync(fd);
    close(fd);
}

int pqz_create(const char *const *inputs, int n_inputs, const char *out_path,
               const char *password, cipher_id_t cipher, kdf_level_t level,
               int hybrid, int zlib_level,
               pqz_progress_cb cb, void *cb_user, char *err, size_t errlen) {
    if (n_inputs <= 0) { seterr(err, errlen, "No inputs to compress."); return -1; }
    for (int i = 0; i < n_inputs; i++) {
        if (same_file(inputs[i], out_path)) {
            seterr(err, errlen, "An input is the same as the output file."); return -1;
        }
    }

    int ret = -1;
    FILE *ar = NULL, *cz = NULL, *out = NULL;
    char tmp_out[4096 + 16];

    /* Stage 1: pack inputs into the PQAR archive. */
    ar = open_tmp(err, errlen);
    if (!ar) goto done;
    if (archive_create(inputs, n_inputs, ar, cb, cb_user, err, errlen) != 0) goto done;
    if (fflush(ar) != 0) { seterr(err, errlen, "Temp write error."); goto done; }
    rewind(ar);

    /* Stage 2: compress the archive. */
    cz = open_tmp(err, errlen);
    if (!cz) goto done;
    if (pqz_compress(ar, cz, zlib_level, err, errlen) != 0) goto done;
    fclose(ar); ar = NULL;
    if (fflush(cz) != 0) { seterr(err, errlen, "Temp write error."); goto done; }

    /* compressed size -> progress total for the encrypt stage. */
    long csize = ftell(cz);
    rewind(cz);

    /* Stage 3: encrypt to a sibling temp, then rename onto out_path. */
    if (snprintf(tmp_out, sizeof(tmp_out), "%s.pqz-tmp", out_path) >= (int)sizeof(tmp_out)) {
        seterr(err, errlen, "Output path too long."); goto done;
    }
    out = fopen(tmp_out, "wb");
    if (!out) { seterr(err, errlen, "Cannot create output file."); goto done; }
    if (pqz_encrypt_stream(cz, out, csize > 0 ? (uint64_t)csize : 0,
                           password, cipher, level, hybrid,
                           cb, cb_user, err, errlen) != 0) goto done;

    if (fflush(out) != 0 || fsync(fileno(out)) != 0) {
        seterr(err, errlen, "Write error."); goto done;
    }
    fclose(out); out = NULL;
    if (rename(tmp_out, out_path) != 0) {
        seterr(err, errlen, "Could not write output file."); goto done;
    }
    fsync_parent_dir(out_path);
    ret = 0;

done:
    if (ar) fclose(ar);
    if (cz) fclose(cz);
    if (out) { fclose(out); remove(tmp_out); }
    return ret;
}

int pqz_extract(const char *in_path, const char *dest_dir,
                const char *password,
                pqz_progress_cb cb, void *cb_user, char *err, size_t errlen) {
    int ret = -1;
    FILE *in = NULL, *cz = NULL, *ar = NULL;

    in = fopen(in_path, "rb");
    if (!in) { seterr(err, errlen, "Cannot open input archive."); goto done; }

    /* Stage 1: decrypt to a temp compressed stream. */
    cz = open_tmp(err, errlen);
    if (!cz) goto done;
    if (pqz_decrypt_stream(in, cz, password, cb, cb_user, err, errlen) != 0) goto done;
    fclose(in); in = NULL;
    if (fflush(cz) != 0) { seterr(err, errlen, "Temp write error."); goto done; }
    rewind(cz);

    /* Stage 2: decompress to a temp archive stream. */
    ar = open_tmp(err, errlen);
    if (!ar) goto done;
    if (pqz_decompress(cz, ar, err, errlen) != 0) goto done;
    fclose(cz); cz = NULL;
    if (fflush(ar) != 0) { seterr(err, errlen, "Temp write error."); goto done; }
    rewind(ar);

    /* Stage 3: extract the archive under dest_dir. */
    if (archive_extract(ar, dest_dir, cb, cb_user, err, errlen) != 0) goto done;
    ret = 0;

done:
    if (in) fclose(in);
    if (cz) fclose(cz);
    if (ar) fclose(ar);
    return ret;
}
