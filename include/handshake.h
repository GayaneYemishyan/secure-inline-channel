#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <netinet/in.h>
#include "crypto.h"

/* ------------------------------------------------------------------ */
/* Wire protocol (control channel = its own TCP connection)            */
/* ------------------------------------------------------------------ */
/*
 * Every message: | ver(1) | type(1) | body_len(2, big-endian) | body |
 *
 *   HELLO        (initiator -> responder): nonce_i(32) | dh_pub_i(256)
 *   HELLO_REPLY  (responder -> initiator): nonce_r(32) | dh_pub_r(256) | mac_r(32)
 *   FINISH       (initiator -> responder): mac_i(32)
 *   REKEY_REQ    (responder -> initiator): empty body
 *
 *   transcript = HELLO(full) || HELLO_REPLY(without mac_r)
 *   th         = SHA-256(transcript)       -> HKDF salt in crypto_session_init
 *   mac_r      = HMAC(psk, "RESP" || th)
 *   mac_i      = HMAC(psk, "INIT" || th)
 *
 * The role labels stop a reflected MAC from being accepted, the fresh
 * nonces stop replay of an old handshake, and both DH public keys sit
 * inside the transcript, so a man-in-the-middle without the PSK cannot
 * forge either MAC.
 */
#define HS_VERSION            1
#define HS_HEADER_LEN         4
#define HS_NONCE_LEN          32
#define HS_HASH_LEN           32
#define HS_MAX_BODY           (HS_NONCE_LEN + CRYPTO_DH_PUB_MAX + CRYPTO_HMAC_LEN)

#define HS_DEFAULT_PORT       5555
#define HS_DEFAULT_TIMEOUT_MS 5000
#define HS_RETRY_MIN_MS       500
#define HS_RETRY_MAX_MS       8000
#define HS_PSK_MAX            128

typedef enum {
    HS_MSG_HELLO       = 1,
    HS_MSG_HELLO_REPLY = 2,
    HS_MSG_FINISH      = 3,
    HS_MSG_REKEY_REQ   = 4
} hs_msg_type_t;

/* ------------------------------------------------------------------ */
/* Return codes                                                        */
/* ------------------------------------------------------------------ */

typedef enum {
    HS_OK             =  0,
    HS_ERR_GENERIC    = -1,
    HS_ERR_PARAM      = -2,
    HS_ERR_NET        = -3,   /* connect/accept/send/recv failure        */
    HS_ERR_TIMEOUT    = -4,
    HS_ERR_PROTO      = -5,   /* bad version, type, length, or order     */
    HS_ERR_AUTH       = -6,   /* MAC mismatch: wrong PSK or active MITM  */
    HS_ERR_CRYPTO     = -7,   /* DH / HKDF / RNG failure                 */
    HS_ERR_STATE      = -8
} hs_status_t;

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    crypto_role_t  role;                 /* initiator = Device1          */
    struct in_addr local_ip;             /* control-channel bind address */
    struct in_addr peer_ip;              /* initiator: where to connect  */
    uint16_t       port;                 /* control port (HS_DEFAULT_PORT) */
    uint8_t        psk[HS_PSK_MAX];      /* pre-shared authentication key */
    size_t         psk_len;
    int            timeout_ms;           /* per-step I/O timeout         */
} handshake_config_t;

/* ------------------------------------------------------------------ */
/* Handshake context                                                   */
/* ------------------------------------------------------------------ */

typedef enum {
    HS_STATE_IDLE         = 0,   /* nothing established: DROP protected traffic */
    HS_STATE_CONNECTING   = 1,
    HS_STATE_ESTABLISHED  = 2,
    HS_STATE_FAILED       = 3
} hs_state_t;

/*
 * The control thread writes sessions, the NFQUEUE thread reads them.
 * Two slots are used so a rekey builds the new session in the inactive
 * slot, then flips `active` atomically. The previous slot stays valid
 * for a short grace period so in-flight packets encrypted with the old
 * key can still be opened (the packet handler tries active, then
 * previous).
 */
typedef struct {
    handshake_config_t cfg;

    crypto_session_t   sess[2];
    _Atomic int        active;        /* index of the current session   */
    _Atomic int        has_previous;  /* 1 while the old slot is valid  */
    _Atomic int        state;         /* hs_state_t                     */
    _Atomic int        rekey_wanted;  /* set by data plane / responder  */

    int                ctrl_fd;       /* open control socket, or -1     */
    int                listen_fd;     /* responder only, or -1          */

    pthread_t          thread;
    _Atomic int        stop;
    int                thread_running;
} handshake_ctx_t;

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

/* Copies cfg, sets state to IDLE, initializes fds to -1. */
int  handshake_init(handshake_ctx_t *ctx, const handshake_config_t *cfg);

/* Stops the thread (if any), closes sockets, destroys sessions. */
void handshake_destroy(handshake_ctx_t *ctx);

/*
 * Load a PSK from a file (raw bytes or hex text, trailing newline
 * ignored). Keep the file out of git (.gitignore: *.key, psk*).
 */
int  handshake_load_psk(const char *path, uint8_t *out, size_t cap, size_t *len);

/* ------------------------------------------------------------------ */
/* Running the handshake                                               */
/* ------------------------------------------------------------------ */

/*
 * One blocking handshake on the control channel.
 *   initiator: connects, sends HELLO, verifies HELLO_REPLY, sends FINISH
 *   responder: accepts, verifies HELLO, replies, verifies FINISH
 * On success the new session is installed in the inactive slot and
 * `active` is flipped. On failure no session changes and the state is
 * left untouched for an established session.
 */
int  handshake_run(handshake_ctx_t *ctx);

/*
 * Background mode (what main.c uses): a control thread performs the
 * initial handshake with retry/backoff (HS_RETRY_MIN_MS..HS_RETRY_MAX_MS),
 * then keeps the control socket open and re-handshakes whenever
 * `rekey_wanted` is set, or when the responder sends REKEY_REQ.
 */
int  handshake_start(handshake_ctx_t *ctx);
void handshake_stop(handshake_ctx_t *ctx);

/* ------------------------------------------------------------------ */
/* Interface for the data plane                                        */
/* ------------------------------------------------------------------ */

/* 1 once a session exists. Until then protected traffic must be dropped. */
int  handshake_is_established(const handshake_ctx_t *ctx);

/* Current session (for sealing and first-try opening), or NULL. */
crypto_session_t *handshake_active_session(handshake_ctx_t *ctx);

/* Previous session during the rekey grace period, or NULL. */
crypto_session_t *handshake_previous_session(handshake_ctx_t *ctx);

/*
 * Ask for a rekey (data plane calls this when
 * crypto_session_needs_rekey() returns 1). Initiator re-handshakes
 * itself; responder sends REKEY_REQ. Non-blocking.
 */
void handshake_request_rekey(handshake_ctx_t *ctx);

/* Drop the previous session (called after the grace period). */
void handshake_retire_previous(handshake_ctx_t *ctx);

/* Human-readable status text for logging. */
const char *handshake_strerror(int status);

#endif /* HANDSHAKE_H */

