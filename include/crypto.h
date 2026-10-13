#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define CRYPTO_KEY_LEN        32      /* AES-256 key                     */
#define CRYPTO_NONCE_LEN      12      /* 96-bit GCM nonce                */
#define CRYPTO_NONCE_PFX_LEN  4       /* fixed per-direction part        */
#define CRYPTO_COUNTER_LEN    8       /* 64-bit explicit packet counter  */
#define CRYPTO_TAG_LEN        16      /* GCM authentication tag          */
#define CRYPTO_HMAC_LEN       32      /* HMAC-SHA256 output              */

/* Classic finite-field DH, RFC 7919 group ffdhe2048 (256-byte public key) */
#define CRYPTO_DH_GROUP       "ffdhe2048"
#define CRYPTO_DH_PUB_MAX     256

/*
 * Bytes added to every protected payload:
 *   protected = ciphertext || tag (16) || counter (8, big-endian)
 */
#define CRYPTO_OVERHEAD       (CRYPTO_TAG_LEN + CRYPTO_COUNTER_LEN)

/* Rekey limits (packets per session key) */
#define CRYPTO_REKEY_SOFT     (1ULL << 30)   /* ask handshake to rekey   */
#define CRYPTO_REKEY_HARD     (1ULL << 32)   /* refuse to encrypt more   */

/* Anti-replay sliding window size (packets) */
#define CRYPTO_REPLAY_WINDOW  64

/* ------------------------------------------------------------------ */
/* Return codes                                                        */
/* ------------------------------------------------------------------ */

typedef enum {
    CRYPTO_OK            =  0,
    CRYPTO_ERR_GENERIC   = -1,
    CRYPTO_ERR_PARAM     = -2,   /* bad argument / buffer too small      */
    CRYPTO_ERR_AUTH      = -3,   /* GCM tag verification failed          */
    CRYPTO_ERR_REPLAY    = -4,   /* counter replayed or too old          */
    CRYPTO_ERR_EXHAUSTED = -5,   /* hard packet limit reached, rekey     */
    CRYPTO_ERR_SHORT     = -6    /* protected payload shorter than overhead */
} crypto_status_t;

/* Which side of the handshake this device played */
typedef enum {
    CRYPTO_ROLE_INITIATOR = 0,   /* e.g. Device1 */
    CRYPTO_ROLE_RESPONDER = 1    /* e.g. Device2 */
} crypto_role_t;

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

/* Ephemeral DH key pair (private part never leaves OpenSSL) */
typedef struct {
    EVP_PKEY *pkey;
} crypto_dh_t;

/* Per-direction receive replay state */
typedef struct {
    uint64_t highest;            /* highest counter accepted so far      */
    uint64_t bitmap;             /* bit i set => (highest - i) was seen  */
    int      initialized;
} crypto_replay_t;

/*
 * Established session. One instance per peer.
 * Each direction has its own key and nonce prefix.
 * Not thread-safe: use from a single NFQUEUE thread, or add a lock.
 */
typedef struct {
    uint8_t  tx_key[CRYPTO_KEY_LEN];
    uint8_t  rx_key[CRYPTO_KEY_LEN];
    uint8_t  tx_nonce_pfx[CRYPTO_NONCE_PFX_LEN];
    uint8_t  rx_nonce_pfx[CRYPTO_NONCE_PFX_LEN];
    uint64_t tx_counter;         /* next counter to use; starts at 0     */
    crypto_replay_t rx_replay;
    EVP_CIPHER_CTX *tx_ctx;      /* reusable contexts (performance)      */
    EVP_CIPHER_CTX *rx_ctx;
} crypto_session_t;

/* ------------------------------------------------------------------ */
/* Library lifecycle & utilities                                       */
/* ------------------------------------------------------------------ */

/* Call once at startup / shutdown. */
int  crypto_init(void);
void crypto_cleanup(void);

/* Cryptographically secure random bytes (OpenSSL RAND_bytes). */
int  crypto_random(uint8_t *buf, size_t len);

/* Wipes memory in a way the compiler cannot optimize away. */
void crypto_secure_zero(void *buf, size_t len);

/* Constant-time comparison. Returns 1 if equal, 0 otherwise. */
int  crypto_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* ------------------------------------------------------------------ */
/* Diffie-Hellman                                                      */
/* ------------------------------------------------------------------ */

/* Generate an ephemeral key pair. */
int  crypto_dh_generate(crypto_dh_t *dh);

/*
 * Export our public key (big-endian, fixed length for the group).
 * *len: in = capacity of out, out = bytes written.
 */
int  crypto_dh_export_public(const crypto_dh_t *dh, uint8_t *out, size_t *len);

/*
 * Compute the raw shared secret from the peer's public key.
 * Validates the peer key (rejects 0, 1, p-1 and out-of-range values).
 * *secret_len: in = capacity, out = bytes written.
 * The raw secret must NOT be used as a key directly: pass it to
 * crypto_session_init().
 */
int  crypto_dh_compute_shared(const crypto_dh_t *dh,
                              const uint8_t *peer_pub, size_t peer_len,
                              uint8_t *secret, size_t *secret_len);

void crypto_dh_free(crypto_dh_t *dh);

/* ------------------------------------------------------------------ */
/* KDF / MAC (used by handshake for key derivation and authentication) */
/* ------------------------------------------------------------------ */

/* HKDF-SHA256 (extract + expand). */
int  crypto_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm,  size_t ikm_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len);

/* HMAC-SHA256, e.g. PSK authentication of the handshake transcript. */
int  crypto_hmac_sha256(const uint8_t *key,  size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[CRYPTO_HMAC_LEN]);

/* ------------------------------------------------------------------ */
/* Session                                                             */
/* ------------------------------------------------------------------ */

/*
 * Derive both directions' keys and nonce prefixes from the DH secret.
 * transcript_hash binds the keys to the handshake messages (used as HKDF
 * salt). Direction assignment depends on role, so the initiator's tx key
 * equals the responder's rx key and vice versa.
 */
int  crypto_session_init(crypto_session_t *s, crypto_role_t role,
                         const uint8_t *shared_secret, size_t secret_len,
                         const uint8_t *transcript_hash, size_t hash_len);

/* Zeroizes keys and frees contexts. */
void crypto_session_destroy(crypto_session_t *s);

/* Returns 1 if the soft limit was reached and a rekey should start. */
int  crypto_session_needs_rekey(const crypto_session_t *s);

/* ------------------------------------------------------------------ */
/* Per-packet AEAD                                                     */
/* ------------------------------------------------------------------ */

/*
 * Protect one TCP payload.
 *   out = ciphertext (pt_len) || tag (16) || counter (8, big-endian)
 *   *out_len = pt_len + CRYPTO_OVERHEAD
 * The nonce is nonce_pfx(4) || counter(8). The counter is incremented
 * after every successful call, so a nonce is never reused with a key.
 * aad: immutable header fields (IPs, ports, ...) to authenticate.
 * Returns CRYPTO_ERR_EXHAUSTED once CRYPTO_REKEY_HARD is reached.
 */
int  crypto_session_seal(crypto_session_t *s,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * Verify and decrypt one protected payload.
 * Order: parse counter -> replay pre-check -> verify tag + decrypt ->
 * only then update the replay window (so forged packets cannot
 * advance it). On any failure nothing is written to the output
 * and the caller must drop the packet.
 *   *pt_len = in_len - CRYPTO_OVERHEAD
 */
int  crypto_session_open(crypto_session_t *s,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *in, size_t in_len,
                         uint8_t *pt, size_t pt_cap, size_t *pt_len);

/* ------------------------------------------------------------------ */
/* Low-level AES-256-GCM (used by the session functions)               */
/* ------------------------------------------------------------------ */

int  crypto_aes_gcm_encrypt(EVP_CIPHER_CTX *ctx,
                            const uint8_t key[CRYPTO_KEY_LEN],
                            const uint8_t nonce[CRYPTO_NONCE_LEN],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t *ct, uint8_t tag[CRYPTO_TAG_LEN]);

/* Returns CRYPTO_ERR_AUTH if the tag does not verify. */
int  crypto_aes_gcm_decrypt(EVP_CIPHER_CTX *ctx,
                            const uint8_t key[CRYPTO_KEY_LEN],
                            const uint8_t nonce[CRYPTO_NONCE_LEN],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct, size_t ct_len,
                            const uint8_t tag[CRYPTO_TAG_LEN],
                            uint8_t *pt);

/* Replay window helpers (exposed for unit tests). */
int  crypto_replay_check(const crypto_replay_t *r, uint64_t counter);
void crypto_replay_update(crypto_replay_t *r, uint64_t counter);

#endif /* CRYPTO_H */