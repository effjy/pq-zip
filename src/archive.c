/*
 * archive.c - PQ-Zip internal archive format ("PQAR"). See archive.h for the
 * on-stream layout. Directories are walked recursively in directory order;
 * each input keeps its basename as the top of its stored path so extraction
 * recreates "file.txt" or "project/sub/file" under the destination.
 */
#include "archive.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#define AR_MAGIC     "PQAR\0\0\0\1"
#define AR_MAGIC_LEN 8
#define AR_DIR       'D'
#define AR_FILE      'F'
#define IO_BUF       65536
#define MAX_PATH_LEN 4096

static void seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg);
}

static void put_u16(uint8_t *b, uint16_t v) { b[0] = v & 0xff; b[1] = (v >> 8) & 0xff; }
static void put_u32(uint8_t *b, uint32_t v) {
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff; b[2] = (v >> 16) & 0xff; b[3] = (v >> 24) & 0xff;
}
static void put_u64(uint8_t *b, uint64_t v) {
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}
static uint16_t get_u16(const uint8_t *b) { return (uint16_t)b[0] | ((uint16_t)b[1] << 8); }
static uint32_t get_u32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static uint64_t get_u64(const uint8_t *b) {
    uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i); return v;
}

/* ----- packing ---------------------------------------------------------- */

typedef struct {
    FILE *out;
    archive_progress_cb cb;
    void *cb_user;
    uint64_t done;
    uint64_t total;
    char *err;
    size_t errlen;
} pack_ctx;

/* Write a directory entry header. */
static int write_dir_entry(pack_ctx *c, const char *relpath) {
    size_t plen = strlen(relpath);
    if (plen > 0xffff) { seterr(c->err, c->errlen, "Path too long."); return -1; }
    uint8_t h[3];
    h[0] = AR_DIR; put_u16(h + 1, (uint16_t)plen);
    if (fwrite(h, 1, 3, c->out) != 3 ||
        fwrite(relpath, 1, plen, c->out) != plen) {
        seterr(c->err, c->errlen, "Write error."); return -1;
    }
    return 0;
}

/* Write a file entry header and its contents. */
static int write_file_entry(pack_ctx *c, const char *abspath, const char *relpath,
                            const struct stat *st) {
    size_t plen = strlen(relpath);
    if (plen > 0xffff) { seterr(c->err, c->errlen, "Path too long."); return -1; }

    FILE *f = fopen(abspath, "rb");
    if (!f) { seterr(c->err, c->errlen, "Cannot open input file."); return -1; }

    /* Layout: [type][plen][path][mode][size][data] -- the path comes before
     * the file metadata, matching archive_extract and the format docs. */
    uint8_t h[3];
    h[0] = AR_FILE; put_u16(h + 1, (uint16_t)plen);
    uint8_t meta[4 + 8];
    put_u32(meta, (uint32_t)(st->st_mode & 0777));
    put_u64(meta + 4, (uint64_t)st->st_size);
    if (fwrite(h, 1, sizeof(h), c->out) != sizeof(h) ||
        fwrite(relpath, 1, plen, c->out) != plen ||
        fwrite(meta, 1, sizeof(meta), c->out) != sizeof(meta)) {
        seterr(c->err, c->errlen, "Write error."); fclose(f); return -1;
    }

    uint8_t buf[IO_BUF];
    uint64_t written = 0;
    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), f);
        if (n == 0) {
            if (ferror(f)) { seterr(c->err, c->errlen, "Read error."); fclose(f); return -1; }
            break;
        }
        if (fwrite(buf, 1, n, c->out) != n) {
            seterr(c->err, c->errlen, "Write error."); fclose(f); return -1;
        }
        written += n;
        c->done += n;
        if (c->cb && c->cb(c->done, c->total, c->cb_user) != 0) {
            seterr(c->err, c->errlen, "Cancelled."); fclose(f); return -1;
        }
        if (written >= (uint64_t)st->st_size) break;  /* don't over-read a growing file */
    }
    fclose(f);
    /* Pad with zeros if the file shrank between stat and read, so the stored
     * size always matches the declared size (extraction relies on it). */
    while (written < (uint64_t)st->st_size) {
        uint8_t z[IO_BUF];
        size_t chunk = sizeof(z);
        if ((uint64_t)chunk > (uint64_t)st->st_size - written)
            chunk = (size_t)((uint64_t)st->st_size - written);
        memset(z, 0, chunk);
        if (fwrite(z, 1, chunk, c->out) != chunk) {
            seterr(c->err, c->errlen, "Write error."); return -1;
        }
        written += chunk;
    }
    return 0;
}

/* Recursively pack `abspath` (whose stored path is `relpath`). */
static int pack_path(pack_ctx *c, const char *abspath, const char *relpath) {
    struct stat st;
    if (lstat(abspath, &st) != 0) {
        seterr(c->err, c->errlen, "Cannot stat input."); return -1;
    }
    if (S_ISDIR(st.st_mode)) {
        if (write_dir_entry(c, relpath) != 0) return -1;
        DIR *d = opendir(abspath);
        if (!d) { seterr(c->err, c->errlen, "Cannot open directory."); return -1; }
        struct dirent *de;
        int rc = 0;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
            char child_abs[MAX_PATH_LEN], child_rel[MAX_PATH_LEN];
            if (snprintf(child_abs, sizeof(child_abs), "%s/%s", abspath, de->d_name) >= (int)sizeof(child_abs) ||
                snprintf(child_rel, sizeof(child_rel), "%s/%s", relpath, de->d_name) >= (int)sizeof(child_rel)) {
                seterr(c->err, c->errlen, "Path too long."); rc = -1; break;
            }
            if (pack_path(c, child_abs, child_rel) != 0) { rc = -1; break; }
        }
        closedir(d);
        return rc;
    } else if (S_ISREG(st.st_mode)) {
        return write_file_entry(c, abspath, relpath, &st);
    }
    /* Silently skip symlinks, devices, sockets, etc. */
    return 0;
}

/* Stored top-level name = basename of the input path. */
static const char *base_name(const char *path) {
    const char *slash = strrchr(path, '/');
    const char *base = slash ? slash + 1 : path;
    return *base ? base : path;   /* guard a trailing "/" */
}

int archive_create(const char *const *inputs, int n_inputs, FILE *out,
                   archive_progress_cb cb, void *cb_user,
                   char *err, size_t errlen) {
    if (n_inputs <= 0) { seterr(err, errlen, "No inputs to compress."); return -1; }
    if (fwrite(AR_MAGIC, 1, AR_MAGIC_LEN, out) != AR_MAGIC_LEN) {
        seterr(err, errlen, "Write error."); return -1;
    }
    pack_ctx c = { out, cb, cb_user, 0, archive_input_size(inputs, n_inputs), err, errlen };
    for (int i = 0; i < n_inputs; i++) {
        /* Strip any trailing slashes so base_name() finds the real name. */
        char trimmed[MAX_PATH_LEN];
        if (snprintf(trimmed, sizeof(trimmed), "%s", inputs[i]) >= (int)sizeof(trimmed)) {
            seterr(err, errlen, "Path too long."); return -1;
        }
        size_t tl = strlen(trimmed);
        while (tl > 1 && trimmed[tl - 1] == '/') trimmed[--tl] = '\0';
        if (pack_path(&c, trimmed, base_name(trimmed)) != 0) return -1;
    }
    return 0;
}

/* ----- size estimate ---------------------------------------------------- */

static uint64_t dir_size(const char *abspath) {
    uint64_t total = 0;
    DIR *d = opendir(abspath);
    if (!d) return 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char child[MAX_PATH_LEN];
        if (snprintf(child, sizeof(child), "%s/%s", abspath, de->d_name) >= (int)sizeof(child))
            continue;
        struct stat st;
        if (lstat(child, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) total += dir_size(child);
        else if (S_ISREG(st.st_mode)) total += (uint64_t)st.st_size;
    }
    closedir(d);
    return total;
}

uint64_t archive_input_size(const char *const *inputs, int n_inputs) {
    uint64_t total = 0;
    for (int i = 0; i < n_inputs; i++) {
        struct stat st;
        if (lstat(inputs[i], &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) total += dir_size(inputs[i]);
        else if (S_ISREG(st.st_mode)) total += (uint64_t)st.st_size;
    }
    return total;
}

/* ----- extraction ------------------------------------------------------- */

/* Reject paths that could escape the destination directory: absolute paths,
 * any ".." component, or empty components. */
static int path_is_safe(const char *rel) {
    if (!rel[0] || rel[0] == '/') return 0;
    const char *p = rel;
    while (*p) {
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t len = (size_t)(p - seg);
        if (len == 0) return 0;                              /* "" or "//" */
        if (len == 2 && seg[0] == '.' && seg[1] == '.') return 0;  /* ".." */
        if (*p == '/') p++;
    }
    return 1;
}

/* Create dir and any missing parents (like mkdir -p) under already-validated
 * relative path joined to dest. */
static int mkpath(const char *full) {
    char tmp[MAX_PATH_LEN];
    if (snprintf(tmp, sizeof(tmp), "%s", full) >= (int)sizeof(tmp)) return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* Ensure the parent directory of `full` exists. */
static int ensure_parent(const char *full) {
    char tmp[MAX_PATH_LEN];
    if (snprintf(tmp, sizeof(tmp), "%s", full) >= (int)sizeof(tmp)) return -1;
    char *slash = strrchr(tmp, '/');
    if (!slash || slash == tmp) return 0;
    *slash = '\0';
    return mkpath(tmp);
}

int archive_extract(FILE *in, const char *dest_dir,
                    archive_progress_cb cb, void *cb_user,
                    char *err, size_t errlen) {
    uint8_t magic[AR_MAGIC_LEN];
    if (fread(magic, 1, AR_MAGIC_LEN, in) != AR_MAGIC_LEN ||
        memcmp(magic, AR_MAGIC, AR_MAGIC_LEN) != 0) {
        seterr(err, errlen, "Corrupt archive (bad inner magic)."); return -1;
    }
    if (mkpath(dest_dir) != 0) {
        seterr(err, errlen, "Cannot create destination directory."); return -1;
    }

    uint64_t done = 0;
    for (;;) {
        uint8_t type;
        size_t r = fread(&type, 1, 1, in);
        if (r == 0 && feof(in)) break;       /* clean end */
        if (r != 1) { seterr(err, errlen, "Truncated archive."); return -1; }

        uint8_t lenb[2];
        if (fread(lenb, 1, 2, in) != 2) { seterr(err, errlen, "Truncated archive."); return -1; }
        uint16_t plen = get_u16(lenb);
        if (plen == 0 || plen >= MAX_PATH_LEN) { seterr(err, errlen, "Corrupt archive (path length)."); return -1; }
        char rel[MAX_PATH_LEN];
        if (fread(rel, 1, plen, in) != plen) { seterr(err, errlen, "Truncated archive."); return -1; }
        rel[plen] = '\0';
        if (!path_is_safe(rel)) { seterr(err, errlen, "Unsafe path in archive (rejected)."); return -1; }

        char full[MAX_PATH_LEN];
        if (snprintf(full, sizeof(full), "%s/%s", dest_dir, rel) >= (int)sizeof(full)) {
            seterr(err, errlen, "Path too long."); return -1;
        }

        if (type == AR_DIR) {
            if (mkpath(full) != 0) { seterr(err, errlen, "Cannot create directory."); return -1; }
        } else if (type == AR_FILE) {
            uint8_t meta[4 + 8];
            if (fread(meta, 1, sizeof(meta), in) != sizeof(meta)) {
                seterr(err, errlen, "Truncated archive."); return -1;
            }
            uint32_t mode = get_u32(meta) & 0777;
            uint64_t size = get_u64(meta + 4);
            if (ensure_parent(full) != 0) {
                seterr(err, errlen, "Cannot create parent directory."); return -1;
            }
            FILE *f = fopen(full, "wb");
            if (!f) { seterr(err, errlen, "Cannot create output file."); return -1; }
            uint8_t buf[IO_BUF];
            uint64_t left = size;
            while (left > 0) {
                size_t want = left > sizeof(buf) ? sizeof(buf) : (size_t)left;
                size_t got = fread(buf, 1, want, in);
                if (got != want) { seterr(err, errlen, "Truncated archive."); fclose(f); return -1; }
                if (fwrite(buf, 1, got, f) != got) {
                    seterr(err, errlen, "Write error."); fclose(f); return -1;
                }
                left -= got;
                done += got;
                if (cb && cb(done, 0, cb_user) != 0) {
                    seterr(err, errlen, "Cancelled."); fclose(f); return -1;
                }
            }
            fclose(f);
            chmod(full, (mode_t)mode);
        } else {
            seterr(err, errlen, "Corrupt archive (unknown entry type)."); return -1;
        }
    }
    return 0;
}
