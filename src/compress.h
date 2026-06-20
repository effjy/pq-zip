/*
 * compress.h - PQ-Zip DEFLATE (zlib) compression stage.
 *
 * The middle stage of the .pqz pipeline: archive -> COMPRESS -> encrypt.
 * Both functions stream `in` to `out`. Returns 0 on success, non-zero on
 * failure with err filled.
 */
#ifndef PQZIP_COMPRESS_H
#define PQZIP_COMPRESS_H

#include <stddef.h>
#include <stdio.h>

/* level: 0..9 zlib compression level (6 is a good default). */
int pqz_compress(FILE *in, FILE *out, int level, char *err, size_t errlen);

int pqz_decompress(FILE *in, FILE *out, char *err, size_t errlen);

#endif /* PQZIP_COMPRESS_H */
