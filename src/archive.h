/*
 * archive.h - PQ-Zip internal archive format ("PQAR").
 *
 * The top stage of the .pqz pipeline. archive_create walks the given input
 * files and directories and serialises them into a single byte stream;
 * archive_extract reads that stream back and recreates the tree under a
 * destination directory. The stream is what gets compressed and then
 * encrypted, so file names and the directory layout stay confidential.
 *
 * Stream layout (all integers little-endian):
 *   magic "PQAR\0\0\0\1" (8 bytes)
 *   then entries until EOF, each:
 *     u8   type      ('D' directory, 'F' regular file)
 *     u16  path_len
 *     u8   path[path_len]   relative, '/'-separated, no leading '/' or ".."
 *     if 'F':  u32 mode (permission bits)  u64 size  u8 data[size]
 */
#ifndef PQZIP_ARCHIVE_H
#define PQZIP_ARCHIVE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Progress callback: bytes packed/extracted so far and the total (0 if not
 * yet known). Return non-zero to abort. */
typedef int (*archive_progress_cb)(uint64_t done, uint64_t total, void *user);

/* Pack the n_inputs paths (files and/or directories) into stream `out`.
 * Returns 0 on success, non-zero on failure with err filled. */
int archive_create(const char *const *inputs, int n_inputs, FILE *out,
                   archive_progress_cb cb, void *cb_user,
                   char *err, size_t errlen);

/* Extract a PQAR stream `in` into dest_dir (created if needed).
 * Returns 0 on success, non-zero on failure with err filled. */
int archive_extract(FILE *in, const char *dest_dir,
                    archive_progress_cb cb, void *cb_user,
                    char *err, size_t errlen);

/* Sum the byte size of all regular files reachable from the inputs, for a
 * progress total. Best-effort: returns 0 if it cannot be determined. */
uint64_t archive_input_size(const char *const *inputs, int n_inputs);

#endif /* PQZIP_ARCHIVE_H */
