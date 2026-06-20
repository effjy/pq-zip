/*
 * compress.c - zlib DEFLATE streaming compression for PQ-Zip.
 */
#include "compress.h"

#include <string.h>
#include <zlib.h>

#define CBUF 65536

static void seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg);
}

int pqz_compress(FILE *in, FILE *out, int level, char *err, size_t errlen) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (deflateInit(&zs, level) != Z_OK) {
        seterr(err, errlen, "Compressor init failed."); return -1;
    }

    unsigned char inbuf[CBUF], outbuf[CBUF];
    int flush = Z_NO_FLUSH;
    int ret = -1;

    do {
        size_t n = fread(inbuf, 1, sizeof(inbuf), in);
        if (ferror(in)) { seterr(err, errlen, "Read error."); goto out; }
        flush = feof(in) ? Z_FINISH : Z_NO_FLUSH;
        zs.next_in = inbuf;
        zs.avail_in = (uInt)n;

        do {
            zs.next_out = outbuf;
            zs.avail_out = sizeof(outbuf);
            int zr = deflate(&zs, flush);
            if (zr == Z_STREAM_ERROR) { seterr(err, errlen, "Compression failed."); goto out; }
            size_t have = sizeof(outbuf) - zs.avail_out;
            if (have && fwrite(outbuf, 1, have, out) != have) {
                seterr(err, errlen, "Write error."); goto out;
            }
        } while (zs.avail_out == 0);
    } while (flush != Z_FINISH);

    ret = 0;
out:
    deflateEnd(&zs);
    return ret;
}

int pqz_decompress(FILE *in, FILE *out, char *err, size_t errlen) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK) {
        seterr(err, errlen, "Decompressor init failed."); return -1;
    }

    unsigned char inbuf[CBUF], outbuf[CBUF];
    int ret = -1;
    int zr = Z_OK;

    do {
        size_t n = fread(inbuf, 1, sizeof(inbuf), in);
        if (ferror(in)) { seterr(err, errlen, "Read error."); goto out; }
        if (n == 0) break;
        zs.next_in = inbuf;
        zs.avail_in = (uInt)n;

        do {
            zs.next_out = outbuf;
            zs.avail_out = sizeof(outbuf);
            zr = inflate(&zs, Z_NO_FLUSH);
            if (zr == Z_STREAM_ERROR || zr == Z_NEED_DICT ||
                zr == Z_DATA_ERROR || zr == Z_MEM_ERROR) {
                seterr(err, errlen, "Corrupt compressed data."); goto out;
            }
            size_t have = sizeof(outbuf) - zs.avail_out;
            if (have && fwrite(outbuf, 1, have, out) != have) {
                seterr(err, errlen, "Write error."); goto out;
            }
        } while (zs.avail_out == 0);
    } while (zr != Z_STREAM_END);

    if (zr != Z_STREAM_END) { seterr(err, errlen, "Truncated compressed data."); goto out; }
    ret = 0;
out:
    inflateEnd(&zs);
    return ret;
}
