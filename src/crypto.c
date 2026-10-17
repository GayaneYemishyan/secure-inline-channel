#include "crypto.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#define KDF_INFO_LABEL "secure-inline-channel v1 key schedule"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static void put_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

static uint64_t get_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

/* nonce = prefix(4) || counter(8, big-endian) */
static void make_nonce(uint8_t nonce[CRYPTO_NONCE_LEN],
                       const uint8_t pfx[CRYPTO_NONCE_PFX_LEN],
                       uint64_t counter)
{
    memcpy(nonce, pfx, CRYPTO_NONCE_PFX_LEN);
    put_be64(nonce + CRYPTO_NONCE_PFX_LEN, counter);
}

static int ranges_overlap(const void *a, size_t alen, const void *b, size_t blen)
{
    uintptr_t a0 = (uintptr_t)a, b0 = (uintptr_t)b;
    if (alen == 0 || blen == 0)
        return 0;
    return a0 < b0 + blen && b0 < a0 + alen;
}

/* Prime p of the DH group (caller frees with BN_free). */
static BIGNUM *dh_get_prime(const EVP_PKEY *pkey)
{
    BIGNUM *p = NULL;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p))
        return NULL;
    return p;
}

/* ------------------------------------------------------------------ */
/* Lifecycle & utilities                                               */
/* ------------------------------------------------------------------ */

int crypto_init(void)
{
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) != 1)
        return CRYPTO_ERR_GENERIC;
    if (EVP_aes_256_gcm() == NULL)
        return CRYPTO_ERR_GENERIC;
    return CRYPTO_OK;
}

void crypto_cleanup(void)
{
    /* OpenSSL 3 cleans up automatically at exit. */
    ERR_clear_error();
}

int crypto_random(uint8_t *buf, size_t len)
{
    if (!buf || len > INT_MAX)
        return CRYPTO_ERR_PARAM;
    if (RAND_bytes(buf, (int)len) != 1) {
        ERR_clear_error();
        return CRYPTO_ERR_GENERIC;
    }
    return CRYPTO_OK;
}

void crypto_secure_zero(void *buf, size_t len)
{
    if (buf && len)
        OPENSSL_cleanse(buf, len);
}

int crypto_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0;
}

/* ------------------------------------------------------------------ */
/* Diffie-Hellman (ffdhe2048, OpenSSL 3 EVP API)                       */
/* ------------------------------------------------------------------ */

int crypto_dh_generate(crypto_dh_t *dh)
{
    EVP_PKEY_CTX *ctx = NULL;
    int rc = CRYPTO_ERR_GENERIC;

    if (!dh)
        return CRYPTO_ERR_PARAM;
    dh->pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) != 1)
        goto out;

    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                         (char *)CRYPTO_DH_GROUP, 0),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_CTX_set_params(ctx, params) != 1)
        goto out;
    if (EVP_PKEY_generate(ctx, &dh->pkey) != 1) {
        dh->pkey = NULL;
        goto out;
    }
    rc = CRYPTO_OK;
out:
    EVP_PKEY_CTX_free(ctx);
    ERR_clear_error();
    return rc;
}

int crypto_dh_export_public(const crypto_dh_t *dh, uint8_t *out, size_t *len)
{
    BIGNUM *p = NULL, *pub = NULL;
    int rc = CRYPTO_ERR_GENERIC;

    if (!dh || !dh->pkey || !out || !len)
        return CRYPTO_ERR_PARAM;

    p = dh_get_prime(dh->pkey);
    if (!p)
        goto out;
    int psz = BN_num_bytes(p);
    if (psz <= 0 || psz > CRYPTO_DH_PUB_MAX) {
        rc = CRYPTO_ERR_GENERIC;
        goto out;
    }
    if (*len < (size_t)psz) {
        rc = CRYPTO_ERR_PARAM;
        goto out;
    }
    if (!EVP_PKEY_get_bn_param(dh->pkey, OSSL_PKEY_PARAM_PUB_KEY, &pub))
        goto out;
    /* Fixed length, left-padded with zeros. */
    if (BN_bn2binpad(pub, out, psz) != psz)
        goto out;
    *len = (size_t)psz;
    rc = CRYPTO_OK;
out:
    BN_free(p);
    BN_free(pub);
    ERR_clear_error();
    return rc;
}

int crypto_dh_compute_shared(const crypto_dh_t *dh,
                             const uint8_t *peer_pub, size_t peer_len,
                             uint8_t *secret, size_t *secret_len)
{
    BIGNUM *p = NULL, *pm1 = NULL, *y = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *fctx = NULL, *cctx = NULL, *dctx = NULL;
    EVP_PKEY *peer = NULL;
    size_t need = 0;
    int rc = CRYPTO_ERR_GENERIC;

    if (!dh || !dh->pkey || !peer_pub || !secret || !secret_len)
        return CRYPTO_ERR_PARAM;

    p = dh_get_prime(dh->pkey);
    if (!p)
        goto out;
    int psz = BN_num_bytes(p);
    if (psz <= 0 || peer_len != (size_t)psz) {   /* fixed-length encoding */
        rc = CRYPTO_ERR_PARAM;
        goto out;
    }

    /* Range check: reject 0, 1, p-1 and anything >= p. */
    y = BN_bin2bn(peer_pub, (int)peer_len, NULL);
    pm1 = BN_dup(p);
    if (!y || !pm1 || !BN_sub_word(pm1, 1))
        goto out;
    if (BN_is_zero(y) || BN_is_one(y) || BN_cmp(y, pm1) >= 0) {
        rc = CRYPTO_ERR_PARAM;
        goto out;
    }

    /* Import the peer key into the same named group. */
    bld = OSSL_PARAM_BLD_new();
    if (!bld ||
        !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                         CRYPTO_DH_GROUP, 0) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, y))
        goto out;
    params = OSSL_PARAM_BLD_to_param(bld);
    fctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!params || !fctx || EVP_PKEY_fromdata_init(fctx) != 1 ||
        EVP_PKEY_fromdata(fctx, &peer, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        rc = CRYPTO_ERR_PARAM;
        goto out;
    }

    /* Full validation (includes the subgroup check for ffdhe groups). */
    cctx = EVP_PKEY_CTX_new_from_pkey(NULL, peer, NULL);
    if (!cctx || EVP_PKEY_public_check(cctx) != 1) {
        rc = CRYPTO_ERR_PARAM;
        goto out;
    }

    /* Derive; pad so the secret is always exactly psz bytes. */
    dctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh->pkey, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) != 1)
        goto out;
    unsigned int pad = 1;
    OSSL_PARAM dparams[2] = {
        OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &pad),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_CTX_set_params(dctx, dparams) != 1 ||
        EVP_PKEY_derive_set_peer(dctx, peer) != 1 ||
        EVP_PKEY_derive(dctx, NULL, &need) != 1)
        goto out;
    if (*secret_len < need) {
        rc = CRYPTO_ERR_PARAM;
        goto out;
    }
    if (EVP_PKEY_derive(dctx, secret, &need) != 1)
        goto out;
    *secret_len = need;
    rc = CRYPTO_OK;
out:
    BN_free(p);
    BN_free(pm1);
    BN_clear_free(y);
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(fctx);
    EVP_PKEY_CTX_free(cctx);
    EVP_PKEY_CTX_free(dctx);
    ERR_clear_error();
    return rc;
}

void crypto_dh_free(crypto_dh_t *dh)
{
    if (dh && dh->pkey) {
        EVP_PKEY_free(dh->pkey);
        dh->pkey = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* HKDF / HMAC                                                         */
/* ------------------------------------------------------------------ */

int crypto_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm,  size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5];
    int n = 0, rc = CRYPTO_ERR_GENERIC;

    if (!ikm || ikm_len == 0 || !okm || okm_len == 0 || okm_len > 255 * 32 ||
        (!salt && salt_len) || (!info && info_len))
        return CRYPTO_ERR_PARAM;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        goto out;
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx)
        goto out;

    params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                   (char *)"SHA256", 0);
    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    (void *)ikm, ikm_len);
    if (salt_len)
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                        (void *)salt, salt_len);
    if (info_len)
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                        (void *)info, info_len);
    params[n] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, okm, okm_len, params) != 1)
        goto out;
    rc = CRYPTO_OK;
out:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    ERR_clear_error();
    return rc;
}

int crypto_hmac_sha256(const uint8_t *key,  size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[CRYPTO_HMAC_LEN])
{
    static const uint8_t empty = 0;
    size_t outl = 0;

    if (!key || key_len == 0 || !out || (!data && data_len))
        return CRYPTO_ERR_PARAM;
    if (!data)
        data = &empty;

    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL,
                   key, key_len, data, data_len,
                   out, CRYPTO_HMAC_LEN, &outl) ||
        outl != CRYPTO_HMAC_LEN) {
        ERR_clear_error();
        return CRYPTO_ERR_GENERIC;
    }
    return CRYPTO_OK;
}

/* ------------------------------------------------------------------ */
/* Low-level AES-256-GCM                                               */
/* ------------------------------------------------------------------ */

int crypto_aes_gcm_encrypt(EVP_CIPHER_CTX *ctx,
                           const uint8_t key[CRYPTO_KEY_LEN],
                           const uint8_t nonce[CRYPTO_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct, uint8_t tag[CRYPTO_TAG_LEN])
{
    int outl = 0, owned = 0, rc = CRYPTO_ERR_GENERIC;
    uint8_t fin[CRYPTO_TAG_LEN];

    if (!key || !nonce || !tag || (!pt && pt_len) || (!ct && pt_len) ||
        (!aad && aad_len) || pt_len > INT_MAX || aad_len > INT_MAX)
        return CRYPTO_ERR_PARAM;

    if (!ctx) {
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            return CRYPTO_ERR_GENERIC;
        owned = 1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            CRYPTO_NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;
    if (aad_len &&
        EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1)
        goto out;
    if (pt_len &&
        EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)pt_len) != 1)
        goto out;
    if (EVP_EncryptFinal_ex(ctx, fin, &outl) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                            CRYPTO_TAG_LEN, tag) != 1)
        goto out;
    rc = CRYPTO_OK;
out:
    if (owned)
        EVP_CIPHER_CTX_free(ctx);
    ERR_clear_error();
    return rc;
}

int crypto_aes_gcm_decrypt(EVP_CIPHER_CTX *ctx,
                           const uint8_t key[CRYPTO_KEY_LEN],
                           const uint8_t nonce[CRYPTO_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[CRYPTO_TAG_LEN],
                           uint8_t *pt)
{
    int outl = 0, owned = 0, rc = CRYPTO_ERR_GENERIC;
    uint8_t fin[CRYPTO_TAG_LEN];

    if (!key || !nonce || !tag || (!ct && ct_len) || (!pt && ct_len) ||
        (!aad && aad_len) || ct_len > INT_MAX || aad_len > INT_MAX)
        return CRYPTO_ERR_PARAM;

    if (!ctx) {
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            return CRYPTO_ERR_GENERIC;
        owned = 1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            CRYPTO_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;
    if (aad_len &&
        EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1)
        goto out;
    if (ct_len &&
        EVP_DecryptUpdate(ctx, pt, &outl, ct, (int)ct_len) != 1)
        goto out;
    /* The expected tag must be set before Final. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                            CRYPTO_TAG_LEN, (void *)tag) != 1)
        goto out;

    if (EVP_DecryptFinal_ex(ctx, fin, &outl) != 1) {
        /* GCM decrypts before verifying: never leak unauthenticated data. */
        crypto_secure_zero(pt, ct_len);
        rc = CRYPTO_ERR_AUTH;
        goto out;
    }
    rc = CRYPTO_OK;
out:
    if (owned)
        EVP_CIPHER_CTX_free(ctx);
    ERR_clear_error();
    return rc;
}

/* ------------------------------------------------------------------ */
/* Replay window                                                       */
/* ------------------------------------------------------------------ */

/* Returns CRYPTO_OK if the counter is acceptable, CRYPTO_ERR_REPLAY if
 * it was already seen or is older than the window. Does not modify r. */
int crypto_replay_check(const crypto_replay_t *r, uint64_t counter)
{
    if (!r)
        return CRYPTO_ERR_PARAM;
    if (!r->initialized || counter > r->highest)
        return CRYPTO_OK;

    uint64_t diff = r->highest - counter;
    if (diff >= CRYPTO_REPLAY_WINDOW)
        return CRYPTO_ERR_REPLAY;               /* too old */
    if (r->bitmap & (1ULL << diff))
        return CRYPTO_ERR_REPLAY;               /* duplicate */
    return CRYPTO_OK;
}

/* Call only after the tag has been verified. */
void crypto_replay_update(crypto_replay_t *r, uint64_t counter)
{
    if (!r)
        return;
    if (!r->initialized) {
        r->highest = counter;
        r->bitmap = 1;
        r->initialized = 1;
        return;
    }
    if (counter > r->highest) {
        uint64_t shift = counter - r->highest;
        r->bitmap = (shift >= CRYPTO_REPLAY_WINDOW) ? 0 : (r->bitmap << shift);
        r->bitmap |= 1;
        r->highest = counter;
    } else {
        uint64_t diff = r->highest - counter;
        if (diff < CRYPTO_REPLAY_WINDOW)
            r->bitmap |= 1ULL << diff;
    }
}

/* ------------------------------------------------------------------ */
/* Session                                                             */
/* ------------------------------------------------------------------ */

/*
 * OKM layout (72 bytes):
 *   [ 0..31] key  initiator -> responder
 *   [32..63] key  responder -> initiator
 *   [64..67] nonce prefix initiator -> responder
 *   [68..71] nonce prefix responder -> initiator
 *
 * The struct is zeroed first: a session slot being reused must have been
 * passed to crypto_session_destroy() beforehand.
 */
int crypto_session_init(crypto_session_t *s, crypto_role_t role,
                        const uint8_t *shared_secret, size_t secret_len,
                        const uint8_t *transcript_hash, size_t hash_len)
{
    uint8_t okm[2 * CRYPTO_KEY_LEN + 2 * CRYPTO_NONCE_PFX_LEN];
    int rc;

    if (!s || !shared_secret || secret_len == 0 ||
        !transcript_hash || hash_len == 0 ||
        (role != CRYPTO_ROLE_INITIATOR && role != CRYPTO_ROLE_RESPONDER))
        return CRYPTO_ERR_PARAM;

    memset(s, 0, sizeof(*s));

    rc = crypto_hkdf_sha256(transcript_hash, hash_len,
                            shared_secret, secret_len,
                            (const uint8_t *)KDF_INFO_LABEL,
                            sizeof(KDF_INFO_LABEL) - 1,
                            okm, sizeof(okm));
    if (rc != CRYPTO_OK)
        goto fail;

    const uint8_t *k_i2r = okm;
    const uint8_t *k_r2i = okm + CRYPTO_KEY_LEN;
    const uint8_t *p_i2r = okm + 2 * CRYPTO_KEY_LEN;
    const uint8_t *p_r2i = p_i2r + CRYPTO_NONCE_PFX_LEN;

    if (role == CRYPTO_ROLE_INITIATOR) {
        memcpy(s->tx_key, k_i2r, CRYPTO_KEY_LEN);
        memcpy(s->rx_key, k_r2i, CRYPTO_KEY_LEN);
        memcpy(s->tx_nonce_pfx, p_i2r, CRYPTO_NONCE_PFX_LEN);
        memcpy(s->rx_nonce_pfx, p_r2i, CRYPTO_NONCE_PFX_LEN);
    } else {
        memcpy(s->tx_key, k_r2i, CRYPTO_KEY_LEN);
        memcpy(s->rx_key, k_i2r, CRYPTO_KEY_LEN);
        memcpy(s->tx_nonce_pfx, p_r2i, CRYPTO_NONCE_PFX_LEN);
        memcpy(s->rx_nonce_pfx, p_i2r, CRYPTO_NONCE_PFX_LEN);
    }

    s->tx_counter = 0;
    s->rx_replay.initialized = 0;

    s->tx_ctx = EVP_CIPHER_CTX_new();
    s->rx_ctx = EVP_CIPHER_CTX_new();
    if (!s->tx_ctx || !s->rx_ctx) {
        rc = CRYPTO_ERR_GENERIC;
        goto fail;
    }

    crypto_secure_zero(okm, sizeof(okm));
    return CRYPTO_OK;

fail:
    crypto_secure_zero(okm, sizeof(okm));
    crypto_session_destroy(s);
    return rc;
}

void crypto_session_destroy(crypto_session_t *s)
{
    if (!s)
        return;
    EVP_CIPHER_CTX_free(s->tx_ctx);   /* NULL-safe */
    EVP_CIPHER_CTX_free(s->rx_ctx);
    OPENSSL_cleanse(s, sizeof(*s));
}

int crypto_session_needs_rekey(const crypto_session_t *s)
{
    return s && s->tx_counter >= CRYPTO_REKEY_SOFT;
}

/* ------------------------------------------------------------------ */
/* Per-packet AEAD                                                     */
/* ------------------------------------------------------------------ */

int crypto_session_seal(crypto_session_t *s,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *pt, size_t pt_len,
                        uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t nonce[CRYPTO_NONCE_LEN];
    uint64_t ctr;
    size_t need;
    int rc;

    if (!s || !s->tx_ctx || !out || !out_len ||
        (!pt && pt_len) || (!aad && aad_len))
        return CRYPTO_ERR_PARAM;
    if (pt_len > SIZE_MAX - CRYPTO_OVERHEAD)
        return CRYPTO_ERR_PARAM;

    need = pt_len + CRYPTO_OVERHEAD;
    if (out_cap < need)
        return CRYPTO_ERR_PARAM;
    /* In-place (out == pt) is fine; partial overlap is not. */
    if (pt != out && ranges_overlap(pt, pt_len, out, need))
        return CRYPTO_ERR_PARAM;
    if (s->tx_counter >= CRYPTO_REKEY_HARD)
        return CRYPTO_ERR_EXHAUSTED;

    /* Consume the counter BEFORE encrypting: a nonce is never reused,
     * even if the encryption below fails. */
    ctr = s->tx_counter++;
    make_nonce(nonce, s->tx_nonce_pfx, ctr);

    rc = crypto_aes_gcm_encrypt(s->tx_ctx, s->tx_key, nonce,
                                aad, aad_len, pt, pt_len,
                                out, out + pt_len);
    if (rc != CRYPTO_OK)
        return rc;

    put_be64(out + pt_len + CRYPTO_TAG_LEN, ctr);
    *out_len = need;
    return CRYPTO_OK;
}

/*
 * `pt` must NOT overlap `in`. GCM writes plaintext before the tag is
 * verified, so on failure the output is wiped; decrypting in place would
 * destroy the input and prevent trying a second (previous) session.
 */
int crypto_session_open(crypto_session_t *s,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *in, size_t in_len,
                        uint8_t *pt, size_t pt_cap, size_t *pt_len)
{
    uint8_t nonce[CRYPTO_NONCE_LEN];
    uint64_t ctr;
    size_t ct_len;
    int rc;

    if (!s || !s->rx_ctx || !in || !pt || !pt_len || (!aad && aad_len))
        return CRYPTO_ERR_PARAM;
    if (in_len < CRYPTO_OVERHEAD)
        return CRYPTO_ERR_SHORT;

    ct_len = in_len - CRYPTO_OVERHEAD;
    if (pt_cap < ct_len)
        return CRYPTO_ERR_PARAM;
    if (ranges_overlap(in, in_len, pt, ct_len))
        return CRYPTO_ERR_PARAM;

    ctr = get_be64(in + ct_len + CRYPTO_TAG_LEN);

    /* Cheap pre-check; the window is only updated after authentication. */
    if (crypto_replay_check(&s->rx_replay, ctr) != CRYPTO_OK)
        return CRYPTO_ERR_REPLAY;

    make_nonce(nonce, s->rx_nonce_pfx, ctr);
    rc = crypto_aes_gcm_decrypt(s->rx_ctx, s->rx_key, nonce,
                                aad, aad_len,
                                in, ct_len,
                                in + ct_len, pt);
    if (rc != CRYPTO_OK)
        return rc;

    crypto_replay_update(&s->rx_replay, ctr);
    *pt_len = ct_len;
    return CRYPTO_OK;
}
