/*
 * crypto.h - PQ-Zip authenticated-encryption layer.
 *
 * This is the bottom stage of the .pqz pipeline:  archive -> compress ->
 * ENCRYPT.  It encrypts/decrypts a byte stream (the compressed archive)
 * using a small AEAD cipher registry and an Argon2id password KDF, with an
 * optional post-quantum hybrid KEM (Kyber-1024 + X448) layered on top.
 *
 * The engine works on already-open FILE* streams; the higher-level pqzip.c
 * owns the temp files, the atomic rename and the .pqz path handling.
 */
#ifndef PQZIP_CRYPTO_H
#define PQZIP_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Cipher identifiers stored in the file header. Never renumber existing
 * values -- only append new ones so old archives keep opening. */
typedef enum {
    CIPHER_AES_256_GCM            = 1,
    CIPHER_XCHACHA20_POLY1305     = 2,
    CIPHER_CHACHA20_POLY1305_IETF = 3,
} cipher_id_t;

/* Key derivation strength presets. Medium is the minimum recommended:
 * 1 GiB memory and multi-lane (parallel) Argon2id. */
typedef enum {
    KDF_BASIC  = 0,
    KDF_MEDIUM = 1,   /* minimum: 1 GiB, parallel */
    KDF_STRONG = 2,
} kdf_level_t;

/* Progress callback: called periodically with bytes processed / total.
 * Return 0 to continue, non-zero to abort the operation. */
typedef int (*pqz_progress_cb)(uint64_t done, uint64_t total, void *user);

/* Initialise the crypto subsystem (libsodium, core-dump hardening).
 * Returns 0 on success. */
int pqz_crypto_init(void);

/* Returns 1 if the given cipher is usable on this machine, else 0.
 * (AES-256-GCM requires hardware AES support.) */
int pqz_cipher_available(cipher_id_t id);

/* Human-readable name for a cipher id, or NULL if unknown. */
const char *pqz_cipher_name(cipher_id_t id);

/* Encrypt the whole of stream `in` into `out`. `total_hint` is the number of
 * plaintext bytes (for progress; 0 if unknown). Returns 0 on success; on
 * failure returns non-zero and fills err (size errlen) with a message. */
int pqz_encrypt_stream(FILE *in, FILE *out, uint64_t total_hint,
                       const char *password, cipher_id_t cipher,
                       kdf_level_t level, int hybrid,
                       pqz_progress_cb cb, void *cb_user,
                       char *err, size_t errlen);

/* Decrypt the whole of stream `in` into `out`. The cipher and KDF parameters
 * are read from the header. Returns 0 on success; non-zero on failure (wrong
 * password, corruption, truncation, etc.). */
int pqz_decrypt_stream(FILE *in, FILE *out,
                       const char *password,
                       pqz_progress_cb cb, void *cb_user,
                       char *err, size_t errlen);

#endif /* PQZIP_CRYPTO_H */
