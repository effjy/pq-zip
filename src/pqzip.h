/*
 * pqzip.h - PQ-Zip high-level pipeline.
 *
 * Compress:  inputs -> archive (PQAR) -> DEFLATE -> AEAD encrypt -> .pqz
 * Extract:   .pqz -> AEAD decrypt -> INFLATE -> archive -> files on disk
 *
 * The intermediate (archived + compressed) stages live in anonymous temp
 * files that are unlinked the moment they are created, so they have no name
 * on disk and vanish automatically when closed.
 */
#ifndef PQZIP_PQZIP_H
#define PQZIP_PQZIP_H

#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

/* Compress + encrypt the inputs (files and/or directories) into out_path
 * (conventionally ending in .pqz). zlib_level is 0..9. Returns 0 on success;
 * on failure non-zero with err filled. */
int pqz_create(const char *const *inputs, int n_inputs, const char *out_path,
               const char *password, cipher_id_t cipher, kdf_level_t level,
               int hybrid, int zlib_level,
               pqz_progress_cb cb, void *cb_user, char *err, size_t errlen);

/* Decrypt + decompress in_path (a .pqz) and extract its contents under
 * dest_dir (created if needed). Returns 0 on success; non-zero with err. */
int pqz_extract(const char *in_path, const char *dest_dir,
                const char *password,
                pqz_progress_cb cb, void *cb_user, char *err, size_t errlen);

#endif /* PQZIP_PQZIP_H */
