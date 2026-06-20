/*
 * crypto.c - PQ-Zip authenticated-encryption layer (stream based).
 *
 * Header layout (all integers little-endian):
 *
 *   offset  size  field
 *   ------  ----  -----------------------------------------------------------
 *   0       8     magic  "PQZIP\0\0\0"
 *   8       1     format_version (1 = password-only, 2 = hybrid KEM)
 *   9       1     cipher_id
 *   10      1     kdf_id (1 = Argon2id)
 *   11      1     kdf_level (informational)
 *   12      4     argon2 t_cost (iterations)
 *   16      4     argon2 m_cost (KiB)
 *   20      4     argon2 parallelism (lanes/threads)
 *   24      16    salt
 *   40      [B]   hybrid block (only when format_version == 2)
 *   ...     N     base nonce (N = cipher nonce length)
 *   ...           sequence of frames
 *
 * Each frame: [uint32 clen][clen bytes AEAD ciphertext+tag]. The plaintext
 * (the compressed archive) is split into 64 KiB chunks. Per-chunk nonce =
 * base nonce with a 64-bit little-endian counter XORed into its trailing 8
 * bytes. Associated data per chunk = counter(8) || final_flag(1), which
 * authenticates chunk ordering and detects truncation of the stream.
 *
 * The hybrid (format version 2) layout, the per-file wrapped secret key and
 * the rationale for not storing public keys are identical to the design used
 * by the sister Ciphers tool.
 */
#include "crypto.h"
#include "hybrid_kem.h"

#include <sodium.h>
#include <argon2.h>

#include <string.h>
#include <stdlib.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define MAGIC          "PQZIP\0\0\0"
#define MAGIC_LEN      8
#define FORMAT_VERSION 1
#define FORMAT_VERSION_HYBRID 2
#define KDF_ID_ARGON2ID 1
#define SALT_LEN       16
#define CHUNK_SIZE     65536
#define MAX_NONCE_LEN  24
#define MAX_TAG_LEN    16

#define HYBRID_MASTERKEY_LEN  crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define WRAP_NONCE_LEN        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define WRAP_ABYTES           crypto_aead_xchacha20poly1305_ietf_ABYTES
#define WRAPPED_SK_LEN        (HK_SK_LEN + WRAP_ABYTES)
#define HYBRID_BLOCK_LEN      (WRAP_NONCE_LEN + WRAPPED_SK_LEN + HK_KEM_CT_LEN)
#define WRAP_AD               ((const unsigned char *)"PQZIP-HYBRID-WRAP")
#define WRAP_AD_LEN           17

/* Upper bounds on KDF parameters accepted from an untrusted header. */
#define MAX_KDF_M_COST    (4u * 1024u * 1024u)  /* KiB = 4 GiB */
#define MAX_KDF_T_COST    16u
#define MAX_KDF_PARALLEL  16u

/* ----- Cipher registry -------------------------------------------------- */

typedef int (*aead_encrypt_fn)(unsigned char *c, unsigned long long *clen,
                               const unsigned char *m, unsigned long long mlen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *nonce, const unsigned char *key);

typedef int (*aead_decrypt_fn)(unsigned char *m, unsigned long long *mlen,
                               const unsigned char *c, unsigned long long clen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *nonce, const unsigned char *key);

static int aes_enc(unsigned char *c, unsigned long long *clen,
                   const unsigned char *m, unsigned long long mlen,
                   const unsigned char *ad, unsigned long long adlen,
                   const unsigned char *n, const unsigned char *k) {
    return crypto_aead_aes256gcm_encrypt(c, clen, m, mlen, ad, adlen, NULL, n, k);
}
static int aes_dec(unsigned char *m, unsigned long long *mlen,
                   const unsigned char *c, unsigned long long clen,
                   const unsigned char *ad, unsigned long long adlen,
                   const unsigned char *n, const unsigned char *k) {
    return crypto_aead_aes256gcm_decrypt(m, mlen, NULL, c, clen, ad, adlen, n, k);
}
static int xchacha_enc(unsigned char *c, unsigned long long *clen,
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char *ad, unsigned long long adlen,
                       const unsigned char *n, const unsigned char *k) {
    return crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, NULL, n, k);
}
static int xchacha_dec(unsigned char *m, unsigned long long *mlen,
                       const unsigned char *c, unsigned long long clen,
                       const unsigned char *ad, unsigned long long adlen,
                       const unsigned char *n, const unsigned char *k) {
    return crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen, NULL, c, clen, ad, adlen, n, k);
}
static int chacha_ietf_enc(unsigned char *c, unsigned long long *clen,
                           const unsigned char *m, unsigned long long mlen,
                           const unsigned char *ad, unsigned long long adlen,
                           const unsigned char *n, const unsigned char *k) {
    return crypto_aead_chacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, NULL, n, k);
}
static int chacha_ietf_dec(unsigned char *m, unsigned long long *mlen,
                           const unsigned char *c, unsigned long long clen,
                           const unsigned char *ad, unsigned long long adlen,
                           const unsigned char *n, const unsigned char *k) {
    return crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen, NULL, c, clen, ad, adlen, n, k);
}

typedef struct {
    cipher_id_t      id;
    const char      *name;
    size_t           key_len;
    size_t           nonce_len;
    size_t           tag_len;
    aead_encrypt_fn  encrypt;
    aead_decrypt_fn  decrypt;
} cipher_t;

static const cipher_t g_ciphers[] = {
    { CIPHER_AES_256_GCM, "AES-256-GCM",
      crypto_aead_aes256gcm_KEYBYTES, crypto_aead_aes256gcm_NPUBBYTES,
      crypto_aead_aes256gcm_ABYTES, aes_enc, aes_dec },
    { CIPHER_XCHACHA20_POLY1305, "XChaCha20-Poly1305",
      crypto_aead_xchacha20poly1305_ietf_KEYBYTES, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
      crypto_aead_xchacha20poly1305_ietf_ABYTES, xchacha_enc, xchacha_dec },
    { CIPHER_CHACHA20_POLY1305_IETF, "ChaCha20-Poly1305",
      crypto_aead_chacha20poly1305_ietf_KEYBYTES, crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
      crypto_aead_chacha20poly1305_ietf_ABYTES, chacha_ietf_enc, chacha_ietf_dec },
};
static const size_t g_ciphers_n = sizeof(g_ciphers) / sizeof(g_ciphers[0]);

static const cipher_t *find_cipher(cipher_id_t id) {
    for (size_t i = 0; i < g_ciphers_n; i++)
        if (g_ciphers[i].id == id) return &g_ciphers[i];
    return NULL;
}

const char *pqz_cipher_name(cipher_id_t id) {
    const cipher_t *c = find_cipher(id);
    return c ? c->name : NULL;
}

int pqz_cipher_available(cipher_id_t id) {
    if (id == CIPHER_AES_256_GCM)
        return crypto_aead_aes256gcm_is_available() ? 1 : 0;
    return find_cipher(id) != NULL;
}

/* ----- KDF -------------------------------------------------------------- */

typedef struct {
    uint32_t t_cost;
    uint32_t m_cost;       /* KiB */
    uint32_t parallelism;
} kdf_params_t;

static void kdf_params_for_level(kdf_level_t level, kdf_params_t *p) {
    switch (level) {
    case KDF_BASIC:
        p->t_cost = 3;  p->m_cost = 256u * 1024u;  p->parallelism = 4; /* 256 MiB */
        break;
    case KDF_STRONG:
        p->t_cost = 4;  p->m_cost = 4u * 1024u * 1024u; p->parallelism = 8; /* 4 GiB */
        break;
    case KDF_MEDIUM:
    default:
        p->t_cost = 3;  p->m_cost = 1u * 1024u * 1024u; p->parallelism = 4; /* 1 GiB */
        break;
    }
}

static int derive_key(const char *password, const uint8_t *salt,
                      const kdf_params_t *p, uint8_t *key, size_t key_len) {
    int rc = argon2id_hash_raw(p->t_cost, p->m_cost, p->parallelism,
                               password, strlen(password),
                               salt, SALT_LEN, key, key_len);
    return rc == ARGON2_OK ? 0 : -1;
}

/* ----- Hybrid KEM helpers ----------------------------------------------- */

static int hybrid_build(const char *password, const uint8_t *salt,
                        const kdf_params_t *kp,
                        uint8_t block[HYBRID_BLOCK_LEN],
                        uint8_t file_key[HK_SHARED_SECRET_LEN]) {
    uint8_t master[HYBRID_MASTERKEY_LEN];
    uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES], x448_pk[HK_X448_PUBKEY_LEN];
    uint8_t hybrid_sk[HK_SK_LEN];   /* kyber_sk || x448_sk */
    int ret = -1;

    sodium_mlock(master, sizeof(master));
    sodium_mlock(hybrid_sk, sizeof(hybrid_sk));

    if (derive_key(password, salt, kp, master, sizeof(master)) != 0) goto out;
    if (hk_generate_keypair(kyber_pk, hybrid_sk,
                            x448_pk, hybrid_sk + HK_KYBER_SECRETKEYBYTES) != 0) goto out;

    uint8_t *p = block;
    uint8_t *wrap_nonce = p;       p += WRAP_NONCE_LEN;
    uint8_t *wrapped_sk = p;       p += WRAPPED_SK_LEN;
    uint8_t *kem_ct     = p;       /* HK_KEM_CT_LEN */

    randombytes_buf(wrap_nonce, WRAP_NONCE_LEN);
    crypto_aead_xchacha20poly1305_ietf_encrypt(wrapped_sk, NULL,
        hybrid_sk, HK_SK_LEN, WRAP_AD, WRAP_AD_LEN, NULL, wrap_nonce, master);

    if (hk_encapsulate(file_key, kem_ct, kyber_pk, x448_pk) != 0) goto out;
    ret = 0;
out:
    sodium_munlock(master, sizeof(master));
    sodium_munlock(hybrid_sk, sizeof(hybrid_sk));
    return ret;
}

static int hybrid_open(const char *password, const uint8_t *salt,
                       const kdf_params_t *kp,
                       const uint8_t block[HYBRID_BLOCK_LEN],
                       uint8_t file_key[HK_SHARED_SECRET_LEN]) {
    uint8_t master[HYBRID_MASTERKEY_LEN];
    uint8_t hybrid_sk[HK_SK_LEN];
    int ret = -1;

    sodium_mlock(master, sizeof(master));
    sodium_mlock(hybrid_sk, sizeof(hybrid_sk));

    const uint8_t *wrap_nonce = block;
    const uint8_t *wrapped_sk = wrap_nonce + WRAP_NONCE_LEN;
    const uint8_t *kem_ct     = wrapped_sk + WRAPPED_SK_LEN;

    if (derive_key(password, salt, kp, master, sizeof(master)) != 0) goto out;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(hybrid_sk, NULL, NULL,
            wrapped_sk, WRAPPED_SK_LEN, WRAP_AD, WRAP_AD_LEN, wrap_nonce, master) != 0)
        goto out;   /* wrong password or tampered key material */

    if (hk_decapsulate(file_key, kem_ct, hybrid_sk,
                       hybrid_sk + HK_KYBER_SECRETKEYBYTES) != 0) goto out;
    ret = 0;
out:
    sodium_munlock(master, sizeof(master));
    sodium_munlock(hybrid_sk, sizeof(hybrid_sk));
    return ret;
}

/* ----- Little-endian helpers ------------------------------------------- */

static void put_u32(uint8_t *b, uint32_t v) {
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff; b[3] = (v >> 24) & 0xff;
}
static uint32_t get_u32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void chunk_nonce(uint8_t *out, const uint8_t *base, size_t nlen, uint64_t ctr) {
    memcpy(out, base, nlen);
    for (int i = 0; i < 8; i++)
        out[nlen - 8 + i] ^= (uint8_t)((ctr >> (8 * i)) & 0xff);
}

static void put_ad(uint8_t ad[9], uint64_t ctr, int final) {
    put_u32(ad, (uint32_t)(ctr & 0xffffffff));
    ad[4] = (uint8_t)((ctr >> 32) & 0xff);
    ad[5] = (uint8_t)((ctr >> 40) & 0xff);
    ad[6] = (uint8_t)((ctr >> 48) & 0xff);
    ad[7] = (uint8_t)((ctr >> 56) & 0xff);
    ad[8] = (uint8_t)final;
}

static void seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) { snprintf(err, errlen, "%s", msg); }
}

/* ----- Public API ------------------------------------------------------- */

int pqz_crypto_init(void) {
    if (sodium_init() < 0) return -1;

    /* Keep secrets off disk: disable core dumps (which can contain the derived
     * key, password and plaintext) and, on Linux, clear the dumpable flag. */
    struct rlimit rl = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    return 0;
}

int pqz_encrypt_stream(FILE *in, FILE *out, uint64_t total_hint,
                       const char *password, cipher_id_t cipher_id,
                       kdf_level_t level, int hybrid,
                       pqz_progress_cb cb, void *cb_user,
                       char *err, size_t errlen) {
    if (!password || !*password) {
        seterr(err, errlen, "A password is required."); return -1;
    }
    const cipher_t *cph = find_cipher(cipher_id);
    if (!cph) { seterr(err, errlen, "Unknown cipher."); return -1; }
    if (hybrid && cph->key_len != HK_SHARED_SECRET_LEN) {
        seterr(err, errlen, "Hybrid mode requires a 256-bit cipher key."); return -1;
    }
    if (!pqz_cipher_available(cipher_id)) {
        seterr(err, errlen, "Cipher not supported on this CPU (AES-256-GCM needs hardware AES).");
        return -1;
    }

    int ret = -1;
    uint8_t key[64];
    uint8_t salt[SALT_LEN];
    uint8_t base_nonce[MAX_NONCE_LEN];
    sodium_mlock(key, sizeof(key));
    kdf_params_t kp;
    kdf_params_for_level(level, &kp);

    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(base_nonce, cph->nonce_len);

    uint8_t *hybrid_block = NULL;
    if (hybrid) {
        hybrid_block = malloc(HYBRID_BLOCK_LEN);
        if (!hybrid_block) { seterr(err, errlen, "Out of memory."); goto done; }
        if (hybrid_build(password, salt, &kp, hybrid_block, key) != 0) {
            seterr(err, errlen, "Hybrid key setup failed (KDF memory, or crypto error).");
            goto done;
        }
    } else if (derive_key(password, salt, &kp, key, cph->key_len) != 0) {
        seterr(err, errlen, "Key derivation failed (insufficient memory for this KDF level?).");
        goto done;
    }

    uint8_t hdr[40];
    memcpy(hdr, MAGIC, MAGIC_LEN);
    hdr[8]  = hybrid ? FORMAT_VERSION_HYBRID : FORMAT_VERSION;
    hdr[9]  = (uint8_t)cipher_id;
    hdr[10] = KDF_ID_ARGON2ID;
    hdr[11] = (uint8_t)level;
    put_u32(hdr + 12, kp.t_cost);
    put_u32(hdr + 16, kp.m_cost);
    put_u32(hdr + 20, kp.parallelism);
    memcpy(hdr + 24, salt, SALT_LEN);
    if (fwrite(hdr, 1, sizeof(hdr), out) != sizeof(hdr) ||
        (hybrid && fwrite(hybrid_block, 1, HYBRID_BLOCK_LEN, out) != HYBRID_BLOCK_LEN) ||
        fwrite(base_nonce, 1, cph->nonce_len, out) != cph->nonce_len) {
        seterr(err, errlen, "Write error."); goto done;
    }

    uint8_t  plain[CHUNK_SIZE];
    uint8_t  ct[CHUNK_SIZE + MAX_TAG_LEN];
    uint8_t  nonce[MAX_NONCE_LEN];
    uint8_t  ad[9];
    uint8_t  lenbuf[4];
    uint64_t ctr = 0, done_bytes = 0;
    sodium_mlock(plain, sizeof(plain));

    for (;;) {
        size_t n = fread(plain, 1, CHUNK_SIZE, in);
        if (n == 0 && !feof(in)) { seterr(err, errlen, "Read error."); goto done; }
        int final = feof(in) ? 1 : 0;

        put_ad(ad, ctr, final);
        chunk_nonce(nonce, base_nonce, cph->nonce_len, ctr);

        unsigned long long clen = 0;
        if (cph->encrypt(ct, &clen, plain, n, ad, sizeof(ad), nonce, key) != 0) {
            seterr(err, errlen, "Encryption failed."); goto done;
        }
        put_u32(lenbuf, (uint32_t)clen);
        if (fwrite(lenbuf, 1, 4, out) != 4 ||
            fwrite(ct, 1, (size_t)clen, out) != (size_t)clen) {
            seterr(err, errlen, "Write error."); goto done;
        }

        done_bytes += n;
        if (cb && cb(done_bytes, total_hint, cb_user) != 0) {
            seterr(err, errlen, "Cancelled."); goto done;
        }
        ctr++;
        if (final) break;
    }

    ret = 0;
done:
    sodium_munlock(key, sizeof(key));
    sodium_munlock(plain, sizeof(plain));
    free(hybrid_block);
    return ret;
}

int pqz_decrypt_stream(FILE *in, FILE *out,
                       const char *password,
                       pqz_progress_cb cb, void *cb_user,
                       char *err, size_t errlen) {
    int ret = -1;
    uint8_t key[64];
    sodium_mlock(key, sizeof(key));

    uint8_t hdr[40];
    if (fread(hdr, 1, sizeof(hdr), in) != sizeof(hdr) ||
        memcmp(hdr, MAGIC, MAGIC_LEN) != 0) {
        seterr(err, errlen, "Not a PQ-Zip archive (bad magic)."); goto done;
    }
    int hybrid = (hdr[8] == FORMAT_VERSION_HYBRID);
    if (hdr[8] != FORMAT_VERSION && !hybrid) {
        seterr(err, errlen, "Unsupported archive format version."); goto done;
    }
    cipher_id_t cipher_id = (cipher_id_t)hdr[9];
    const cipher_t *cph = find_cipher(cipher_id);
    if (!cph) { seterr(err, errlen, "Unknown cipher in archive."); goto done; }
    if (!pqz_cipher_available(cipher_id)) {
        seterr(err, errlen, "Cipher in archive not supported on this CPU."); goto done;
    }
    if (hdr[10] != KDF_ID_ARGON2ID) {
        seterr(err, errlen, "Unknown KDF in archive."); goto done;
    }

    kdf_params_t kp;
    kp.t_cost = get_u32(hdr + 12);
    kp.m_cost = get_u32(hdr + 16);
    kp.parallelism = get_u32(hdr + 20);

    if (kp.t_cost == 0 || kp.t_cost > MAX_KDF_T_COST ||
        kp.parallelism == 0 || kp.parallelism > MAX_KDF_PARALLEL ||
        kp.m_cost < 8u * kp.parallelism || kp.m_cost > MAX_KDF_M_COST) {
        seterr(err, errlen, "Invalid or unsafe KDF parameters in archive."); goto done;
    }

    if (hybrid) {
        if (cph->key_len != HK_SHARED_SECRET_LEN) {
            seterr(err, errlen, "Hybrid archive uses an unsupported cipher key length."); goto done;
        }
        uint8_t *hybrid_block = malloc(HYBRID_BLOCK_LEN);
        if (!hybrid_block) { seterr(err, errlen, "Out of memory."); goto done; }
        if (fread(hybrid_block, 1, HYBRID_BLOCK_LEN, in) != HYBRID_BLOCK_LEN) {
            seterr(err, errlen, "Truncated header."); free(hybrid_block); goto done;
        }
        int hrc = hybrid_open(password, hdr + 24, &kp, hybrid_block, key);
        free(hybrid_block);
        if (hrc != 0) {
            seterr(err, errlen, "Decryption failed: wrong password or corrupted/tampered archive.");
            goto done;
        }
    }

    uint8_t base_nonce[MAX_NONCE_LEN];
    if (fread(base_nonce, 1, cph->nonce_len, in) != cph->nonce_len) {
        seterr(err, errlen, "Truncated header."); goto done;
    }

    if (!hybrid && derive_key(password, hdr + 24, &kp, key, cph->key_len) != 0) {
        seterr(err, errlen, "Key derivation failed."); goto done;
    }

    /* total = remaining file size for progress. */
    uint64_t total = 0;
    long cur = ftell(in);
    if (cur >= 0 && fseek(in, 0, SEEK_END) == 0) {
        long e = ftell(in);
        if (e > cur) total = (uint64_t)(e - cur);
        fseek(in, cur, SEEK_SET);
    }

    uint8_t  ct[CHUNK_SIZE + MAX_TAG_LEN];
    uint8_t  plain[CHUNK_SIZE + MAX_TAG_LEN];
    uint8_t  nonce[MAX_NONCE_LEN];
    uint8_t  ad[9];
    uint8_t  lenbuf[4];
    uint64_t ctr = 0, done_bytes = 0;
    int saw_final = 0;
    sodium_mlock(plain, sizeof(plain));

    for (;;) {
        size_t r = fread(lenbuf, 1, 4, in);
        if (r == 0 && feof(in)) break;          /* clean end of frames */
        if (r != 4) { seterr(err, errlen, "Truncated archive."); goto done; }
        uint32_t clen = get_u32(lenbuf);
        if (clen > sizeof(ct) || clen < cph->tag_len) {
            seterr(err, errlen, "Corrupt frame length."); goto done;
        }
        if (fread(ct, 1, clen, in) != clen) {
            seterr(err, errlen, "Truncated archive."); goto done;
        }

        int final = 0;
        int ch = fgetc(in);
        if (ch == EOF) final = 1; else ungetc(ch, in);

        put_ad(ad, ctr, final);
        chunk_nonce(nonce, base_nonce, cph->nonce_len, ctr);

        unsigned long long mlen = 0;
        if (cph->decrypt(plain, &mlen, ct, clen, ad, sizeof(ad), nonce, key) != 0) {
            seterr(err, errlen, "Decryption failed: wrong password or corrupted/tampered archive.");
            goto done;
        }
        if (mlen && fwrite(plain, 1, (size_t)mlen, out) != (size_t)mlen) {
            seterr(err, errlen, "Write error."); goto done;
        }

        done_bytes += (uint64_t)clen + 4u;
        if (cb && cb(done_bytes, total, cb_user) != 0) {
            seterr(err, errlen, "Cancelled."); goto done;
        }
        ctr++;
        if (final) { saw_final = 1; break; }
    }

    if (!saw_final) { seterr(err, errlen, "Archive is truncated (missing final block)."); goto done; }
    ret = 0;
done:
    sodium_munlock(key, sizeof(key));
    sodium_munlock(plain, sizeof(plain));
    return ret;
}
