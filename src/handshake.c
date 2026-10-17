#define _GNU_SOURCE
#include "handshake.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#define HS_MSG_MAX        (HS_HEADER_LEN + HS_MAX_BODY)
#define HS_POLL_SLICE_MS  200
#define HS_DRAIN_US       100000      /* wait before freeing a slot the data plane may touch */
#define HS_REKEY_REQ_GAP  5000        /* min ms between REKEY_REQ messages */

/* ------------------------------------------------------------------ */
/* Small utilities                                                     */
/* ------------------------------------------------------------------ */

static void hs_log(const char *fmt, ...)
{
    va_list ap;
    fputs("[handshake] ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Sleep up to ms, returning early when ctx->stop is set. */
static void sleep_ms(handshake_ctx_t *ctx, unsigned ms)
{
    int64_t end = now_ms() + ms;
    while (!atomic_load(&ctx->stop) && now_ms() < end)
        usleep(50 * 1000);
}

const char *handshake_strerror(int status)
{
    switch (status) {
    case HS_OK:          return "ok";
    case HS_ERR_PARAM:   return "invalid parameter";
    case HS_ERR_NET:     return "network error";
    case HS_ERR_TIMEOUT: return "timeout";
    case HS_ERR_PROTO:   return "protocol error";
    case HS_ERR_AUTH:    return "authentication failed (wrong PSK or active attacker)";
    case HS_ERR_CRYPTO:  return "cryptographic failure";
    case HS_ERR_STATE:   return "invalid state";
    default:             return "generic error";
    }
}

/* ------------------------------------------------------------------ */
/* Socket I/O with deadlines (sockets are non-blocking)                */
/* ------------------------------------------------------------------ */

static int wait_fd(int fd, short ev, int64_t deadline)
{
    for (;;) {
        int64_t rem = deadline - now_ms();
        if (rem <= 0)
            return HS_ERR_TIMEOUT;
        struct pollfd p = { .fd = fd, .events = ev };
        int r = poll(&p, 1, rem > INT_MAX ? INT_MAX : (int)rem);
        if (r > 0) {
            if (p.revents & ev)
                return HS_OK;
            if (p.revents & (POLLERR | POLLHUP | POLLNVAL))
                return HS_ERR_NET;
        } else if (r == 0) {
            return HS_ERR_TIMEOUT;
        } else if (errno != EINTR) {
            return HS_ERR_NET;
        }
    }
}

static int send_all(int fd, const uint8_t *buf, size_t len, int64_t deadline)
{
    while (len) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);
        if (n > 0) {
            buf += n;
            len -= (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int w = wait_fd(fd, POLLOUT, deadline);
            if (w != HS_OK)
                return w;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return HS_ERR_NET;
        }
    }
    return HS_OK;
}

static int recv_all(int fd, uint8_t *buf, size_t len, int64_t deadline)
{
    while (len) {
        ssize_t n = recv(fd, buf, len, 0);
        if (n > 0) {
            buf += n;
            len -= (size_t)n;
        } else if (n == 0) {
            return HS_ERR_NET;                       /* peer closed */
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            int w = wait_fd(fd, POLLIN, deadline);
            if (w != HS_OK)
                return w;
        } else if (errno != EINTR) {
            return HS_ERR_NET;
        }
    }
    return HS_OK;
}

static void put_hdr(uint8_t *m, uint8_t type, size_t body_len)
{
    m[0] = HS_VERSION;
    m[1] = type;
    m[2] = (uint8_t)(body_len >> 8);
    m[3] = (uint8_t)(body_len & 0xFF);
}

static int send_msg(int fd, const uint8_t *msg, size_t len, int timeout_ms)
{
    return send_all(fd, msg, len, now_ms() + timeout_ms);
}

/* Receives one whole message (header + body) into msg[HS_MSG_MAX]. */
static int recv_msg(int fd, int timeout_ms, uint8_t *msg, size_t *len, uint8_t *type)
{
    int64_t deadline = now_ms() + timeout_ms;
    int rc = recv_all(fd, msg, HS_HEADER_LEN, deadline);
    if (rc != HS_OK)
        return rc;
    if (msg[0] != HS_VERSION)
        return HS_ERR_PROTO;
    size_t body = ((size_t)msg[2] << 8) | msg[3];
    if (body > HS_MAX_BODY)
        return HS_ERR_PROTO;
    rc = recv_all(fd, msg + HS_HEADER_LEN, body, deadline);
    if (rc != HS_OK)
        return rc;
    *type = msg[1];
    *len = HS_HEADER_LEN + body;
    return HS_OK;
}

static void set_sock_opts(int fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
}

static void close_ctrl(handshake_ctx_t *ctx)
{
    if (ctx->ctrl_fd >= 0) {
        close(ctx->ctrl_fd);
        ctx->ctrl_fd = -1;
    }
}

/* ------------------------------------------------------------------ */
/* Connection management                                               */
/* ------------------------------------------------------------------ */

/* Initiator: connect to the peer's control port. Sets ctx->ctrl_fd. */
static int connect_peer(handshake_ctx_t *ctx)
{
    const handshake_config_t *cfg = &ctx->cfg;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return HS_ERR_NET;

    if (cfg->local_ip.s_addr) {
        struct sockaddr_in la = { .sin_family = AF_INET, .sin_addr = cfg->local_ip };
        if (bind(fd, (struct sockaddr *)&la, sizeof(la)) < 0) {
            close(fd);
            return HS_ERR_NET;
        }
    }

    struct sockaddr_in pa = {
        .sin_family = AF_INET,
        .sin_port   = htons(cfg->port),
        .sin_addr   = cfg->peer_ip
    };
    int r = connect(fd, (struct sockaddr *)&pa, sizeof(pa));
    if (r < 0 && errno != EINPROGRESS) {
        close(fd);
        return HS_ERR_NET;
    }
    if (r < 0) {
        int64_t deadline = now_ms() + cfg->timeout_ms;
        for (;;) {
            if (atomic_load(&ctx->stop)) {
                close(fd);
                return HS_ERR_STATE;
            }
            int64_t slice = now_ms() + HS_POLL_SLICE_MS;
            if (slice > deadline)
                slice = deadline;
            int w = wait_fd(fd, POLLOUT, slice);
            if (w == HS_OK)
                break;
            if (w == HS_ERR_NET || now_ms() >= deadline) {
                close(fd);
                return w == HS_ERR_NET ? HS_ERR_NET : HS_ERR_TIMEOUT;
            }
        }
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err) {
            close(fd);
            return HS_ERR_NET;
        }
    }
    set_sock_opts(fd);
    ctx->ctrl_fd = fd;
    return HS_OK;
}

/* Responder: create the listening socket if needed. */
static int open_listener(handshake_ctx_t *ctx)
{
    if (ctx->listen_fd >= 0)
        return HS_OK;
    const handshake_config_t *cfg = &ctx->cfg;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return HS_ERR_NET;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in la = {
        .sin_family = AF_INET,
        .sin_port   = htons(cfg->port),
        .sin_addr   = cfg->local_ip            /* 0.0.0.0 if unset */
    };
    if (bind(fd, (struct sockaddr *)&la, sizeof(la)) < 0 || listen(fd, 1) < 0) {
        hs_log("cannot listen on port %u: %s", cfg->port, strerror(errno));
        close(fd);
        return HS_ERR_NET;
    }
    ctx->listen_fd = fd;
    return HS_OK;
}

/* Accepts one connection; only the configured peer IP is allowed. */
static int accept_one(handshake_ctx_t *ctx)
{
    struct sockaddr_in a;
    socklen_t l = sizeof(a);
    int fd = accept4(ctx->listen_fd, (struct sockaddr *)&a, &l,
                     SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0)
        return -1;
    if (a.sin_addr.s_addr != ctx->cfg.peer_ip.s_addr) {
        hs_log("rejected control connection from unexpected address");
        close(fd);
        return -1;
    }
    set_sock_opts(fd);
    return fd;
}

/* Responder (blocking mode): wait for the initiator, up to timeout_ms. */
static int accept_peer(handshake_ctx_t *ctx, int timeout_ms)
{
    int rc = open_listener(ctx);
    if (rc != HS_OK)
        return rc;
    int64_t deadline = now_ms() + timeout_ms;
    while (!atomic_load(&ctx->stop)) {
        int64_t slice = now_ms() + HS_POLL_SLICE_MS;
        if (slice > deadline)
            slice = deadline;
        int w = wait_fd(ctx->listen_fd, POLLIN, slice);
        if (w == HS_OK) {
            int fd = accept_one(ctx);
            if (fd >= 0) {
                close_ctrl(ctx);
                ctx->ctrl_fd = fd;
                return HS_OK;
            }
        } else if (w == HS_ERR_NET) {
            return HS_ERR_NET;
        }
        if (now_ms() >= deadline)
            return HS_ERR_TIMEOUT;
    }
    return HS_ERR_STATE;
}

/* ------------------------------------------------------------------ */
/* Transcript hash and MACs                                            */
/* ------------------------------------------------------------------ */

static int transcript_hash(const uint8_t *a, size_t alen,
                           const uint8_t *b, size_t blen,
                           uint8_t out[HS_HASH_LEN])
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned int outl = 0;
    int ok = md &&
             EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(md, a, alen) == 1 &&
             EVP_DigestUpdate(md, b, blen) == 1 &&
             EVP_DigestFinal_ex(md, out, &outl) == 1 &&
             outl == HS_HASH_LEN;
    EVP_MD_CTX_free(md);
    return ok ? HS_OK : HS_ERR_CRYPTO;
}

/* mac = HMAC(psk, label(4) || th(32)); label is "RESP" or "INIT". */
static int compute_mac(const handshake_config_t *cfg, const char label[4],
                       const uint8_t th[HS_HASH_LEN], uint8_t out[CRYPTO_HMAC_LEN])
{
    uint8_t buf[4 + HS_HASH_LEN];
    memcpy(buf, label, 4);
    memcpy(buf + 4, th, HS_HASH_LEN);
    int rc = crypto_hmac_sha256(cfg->psk, cfg->psk_len, buf, sizeof(buf), out);
    return rc == CRYPTO_OK ? HS_OK : HS_ERR_CRYPTO;
}

/* ------------------------------------------------------------------ */
/* Handshake: initiator side                                           */
/* ------------------------------------------------------------------ */

static int hs_initiator(handshake_ctx_t *ctx, int fd, crypto_session_t *out)
{
    const handshake_config_t *cfg = &ctx->cfg;
    crypto_dh_t dh = { NULL };
    uint8_t pub[CRYPTO_DH_PUB_MAX];
    size_t  publen = sizeof(pub);
    uint8_t hello[HS_MSG_MAX], reply[HS_MSG_MAX];
    uint8_t finish[HS_HEADER_LEN + CRYPTO_HMAC_LEN];
    uint8_t th[HS_HASH_LEN], mac[CRYPTO_HMAC_LEN];
    uint8_t secret[CRYPTO_DH_PUB_MAX];
    size_t  secret_len = sizeof(secret);
    size_t  hello_len, reply_len, prefix_len;
    uint8_t type;
    int rc = HS_ERR_CRYPTO;

    if (crypto_dh_generate(&dh) != CRYPTO_OK ||
        crypto_dh_export_public(&dh, pub, &publen) != CRYPTO_OK)
        goto out;

    /* HELLO: nonce_i | dh_pub_i */
    hello_len = HS_HEADER_LEN + HS_NONCE_LEN + publen;
    put_hdr(hello, HS_MSG_HELLO, HS_NONCE_LEN + publen);
    if (crypto_random(hello + HS_HEADER_LEN, HS_NONCE_LEN) != CRYPTO_OK)
        goto out;
    memcpy(hello + HS_HEADER_LEN + HS_NONCE_LEN, pub, publen);
    rc = send_msg(fd, hello, hello_len, cfg->timeout_ms);
    if (rc != HS_OK)
        goto out;

    /* HELLO_REPLY: nonce_r | dh_pub_r | mac_r */
    rc = recv_msg(fd, cfg->timeout_ms, reply, &reply_len, &type);
    if (rc != HS_OK)
        goto out;
    if (type != HS_MSG_HELLO_REPLY ||
        reply_len != HS_HEADER_LEN + HS_NONCE_LEN + publen + CRYPTO_HMAC_LEN) {
        rc = HS_ERR_PROTO;
        goto out;
    }
    prefix_len = reply_len - CRYPTO_HMAC_LEN;

    /* Verify the responder's MAC first: cheap, and it gates the DH work. */
    rc = transcript_hash(hello, hello_len, reply, prefix_len, th);
    if (rc != HS_OK)
        goto out;
    rc = compute_mac(cfg, "RESP", th, mac);
    if (rc != HS_OK)
        goto out;
    if (!crypto_ct_equal(mac, reply + prefix_len, CRYPTO_HMAC_LEN)) {
        rc = HS_ERR_AUTH;
        goto out;
    }

    if (crypto_dh_compute_shared(&dh, reply + HS_HEADER_LEN + HS_NONCE_LEN, publen,
                                 secret, &secret_len) != CRYPTO_OK) {
        rc = HS_ERR_CRYPTO;
        goto out;
    }

    /* FINISH: mac_i */
    put_hdr(finish, HS_MSG_FINISH, CRYPTO_HMAC_LEN);
    rc = compute_mac(cfg, "INIT", th, finish + HS_HEADER_LEN);
    if (rc != HS_OK)
        goto out;
    rc = send_msg(fd, finish, sizeof(finish), cfg->timeout_ms);
    if (rc != HS_OK)
        goto out;

    if (crypto_session_init(out, CRYPTO_ROLE_INITIATOR, secret, secret_len,
                            th, HS_HASH_LEN) != CRYPTO_OK) {
        rc = HS_ERR_CRYPTO;
        goto out;
    }
    rc = HS_OK;
out:
    crypto_secure_zero(secret, sizeof(secret));
    crypto_secure_zero(mac, sizeof(mac));
    crypto_dh_free(&dh);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Handshake: responder side (HELLO already received)                  */
/* ------------------------------------------------------------------ */

static int hs_responder(handshake_ctx_t *ctx, int fd,
                        const uint8_t *hello, size_t hello_len,
                        crypto_session_t *out)
{
    const handshake_config_t *cfg = &ctx->cfg;
    crypto_dh_t dh = { NULL };
    uint8_t pub[CRYPTO_DH_PUB_MAX];
    size_t  publen = sizeof(pub);
    uint8_t reply[HS_MSG_MAX], fin[HS_MSG_MAX];
    uint8_t th[HS_HASH_LEN], mac[CRYPTO_HMAC_LEN];
    uint8_t secret[CRYPTO_DH_PUB_MAX];
    size_t  secret_len = sizeof(secret);
    size_t  prefix_len, fin_len;
    uint8_t type;
    int rc = HS_ERR_CRYPTO;

    if (crypto_dh_generate(&dh) != CRYPTO_OK ||
        crypto_dh_export_public(&dh, pub, &publen) != CRYPTO_OK)
        goto out;

    if (hello_len != HS_HEADER_LEN + HS_NONCE_LEN + publen) {
        rc = HS_ERR_PROTO;
        goto out;
    }
    const uint8_t *peer_pub = hello + HS_HEADER_LEN + HS_NONCE_LEN;

    /* HELLO_REPLY: nonce_r | dh_pub_r | mac_r */
    prefix_len = HS_HEADER_LEN + HS_NONCE_LEN + publen;
    put_hdr(reply, HS_MSG_HELLO_REPLY, HS_NONCE_LEN + publen + CRYPTO_HMAC_LEN);
    if (crypto_random(reply + HS_HEADER_LEN, HS_NONCE_LEN) != CRYPTO_OK)
        goto out;
    memcpy(reply + HS_HEADER_LEN + HS_NONCE_LEN, pub, publen);

    rc = transcript_hash(hello, hello_len, reply, prefix_len, th);
    if (rc != HS_OK)
        goto out;
    rc = compute_mac(cfg, "RESP", th, reply + prefix_len);
    if (rc != HS_OK)
        goto out;
    rc = send_msg(fd, reply, prefix_len + CRYPTO_HMAC_LEN, cfg->timeout_ms);
    if (rc != HS_OK)
        goto out;

    /* FINISH: verify the initiator's MAC before doing any DH work. */
    rc = recv_msg(fd, cfg->timeout_ms, fin, &fin_len, &type);
    if (rc != HS_OK)
        goto out;
    if (type != HS_MSG_FINISH || fin_len != HS_HEADER_LEN + CRYPTO_HMAC_LEN) {
        rc = HS_ERR_PROTO;
        goto out;
    }
    rc = compute_mac(cfg, "INIT", th, mac);
    if (rc != HS_OK)
        goto out;
    if (!crypto_ct_equal(mac, fin + HS_HEADER_LEN, CRYPTO_HMAC_LEN)) {
        rc = HS_ERR_AUTH;
        goto out;
    }

    if (crypto_dh_compute_shared(&dh, peer_pub, publen,
                                 secret, &secret_len) != CRYPTO_OK) {
        rc = HS_ERR_CRYPTO;
        goto out;
    }
    if (crypto_session_init(out, CRYPTO_ROLE_RESPONDER, secret, secret_len,
                            th, HS_HASH_LEN) != CRYPTO_OK) {
        rc = HS_ERR_CRYPTO;
        goto out;
    }
    rc = HS_OK;
out:
    crypto_secure_zero(secret, sizeof(secret));
    crypto_secure_zero(mac, sizeof(mac));
    crypto_dh_free(&dh);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Session installation                                                */
/* ------------------------------------------------------------------ */

/*
 * First session: goes into the active slot.
 * Rekey: built in the inactive slot, then `active` flips and the old
 * session becomes `previous`. The slot being overwritten held the older
 * "previous" session; the data plane may still be inside a call that uses
 * it, so it is hidden first and freed after a short drain delay.
 * `fresh` ownership moves into the slot (it is wiped, not destroyed).
 */
static void install_session(handshake_ctx_t *ctx, crypto_session_t *fresh)
{
    int cur = atomic_load(&ctx->active);

    if (atomic_load(&ctx->state) != HS_STATE_ESTABLISHED) {
        crypto_session_destroy(&ctx->sess[cur]);
        memcpy(&ctx->sess[cur], fresh, sizeof(*fresh));
        crypto_secure_zero(fresh, sizeof(*fresh));
        atomic_store(&ctx->has_previous, 0);
        atomic_store(&ctx->state, HS_STATE_ESTABLISHED);
        hs_log("session established");
    } else {
        int next = 1 - cur;
        atomic_store(&ctx->has_previous, 0);
        if (ctx->sess[next].tx_ctx) {
            usleep(HS_DRAIN_US);
            crypto_session_destroy(&ctx->sess[next]);
        }
        memcpy(&ctx->sess[next], fresh, sizeof(*fresh));
        crypto_secure_zero(fresh, sizeof(*fresh));
        atomic_store(&ctx->active, next);
        atomic_store(&ctx->has_previous, 1);
        hs_log("session rekeyed");
    }
    atomic_store(&ctx->rekey_wanted, 0);
}

static void note_failure(handshake_ctx_t *ctx, int rc)
{
    hs_log("handshake failed: %s", handshake_strerror(rc));
    if (atomic_load(&ctx->state) != HS_STATE_ESTABLISHED)
        atomic_store(&ctx->state,
                     rc == HS_ERR_AUTH ? HS_STATE_FAILED : HS_STATE_CONNECTING);
}

static int initiator_handshake(handshake_ctx_t *ctx)
{
    crypto_session_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    int rc = hs_initiator(ctx, ctx->ctrl_fd, &fresh);
    if (rc == HS_OK)
        install_session(ctx, &fresh);
    return rc;
}

static int responder_handshake(handshake_ctx_t *ctx, const uint8_t *hello, size_t len)
{
    crypto_session_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    int rc = hs_responder(ctx, ctx->ctrl_fd, hello, len, &fresh);
    if (rc == HS_OK)
        install_session(ctx, &fresh);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Blocking single handshake                                           */
/* ------------------------------------------------------------------ */

int handshake_run(handshake_ctx_t *ctx)
{
    int rc;
    if (!ctx)
        return HS_ERR_PARAM;
    if (ctx->thread_running)
        return HS_ERR_STATE;

    if (ctx->cfg.role == CRYPTO_ROLE_INITIATOR) {
        if (ctx->ctrl_fd < 0 && (rc = connect_peer(ctx)) != HS_OK)
            return rc;
        rc = initiator_handshake(ctx);
    } else {
        uint8_t msg[HS_MSG_MAX], type;
        size_t len;
        if (ctx->ctrl_fd < 0 && (rc = accept_peer(ctx, ctx->cfg.timeout_ms)) != HS_OK)
            return rc;
        rc = recv_msg(ctx->ctrl_fd, ctx->cfg.timeout_ms, msg, &len, &type);
        if (rc == HS_OK && type != HS_MSG_HELLO)
            rc = HS_ERR_PROTO;
        if (rc == HS_OK)
            rc = responder_handshake(ctx, msg, len);
    }
    if (rc != HS_OK) {
        note_failure(ctx, rc);
        close_ctrl(ctx);
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* Control thread                                                      */
/* ------------------------------------------------------------------ */

static void initiator_loop(handshake_ctx_t *ctx)
{
    unsigned backoff = HS_RETRY_MIN_MS;
    int need_hs = 1;

    while (!atomic_load(&ctx->stop)) {
        if (ctx->ctrl_fd < 0) {
            int rc = connect_peer(ctx);
            if (rc != HS_OK) {
                sleep_ms(ctx, backoff);
                backoff = backoff * 2 > HS_RETRY_MAX_MS ? HS_RETRY_MAX_MS : backoff * 2;
                continue;
            }
            need_hs = 1;
        }

        if (need_hs || atomic_load(&ctx->rekey_wanted)) {
            int rc = initiator_handshake(ctx);
            if (rc != HS_OK) {
                note_failure(ctx, rc);
                close_ctrl(ctx);
                sleep_ms(ctx, backoff);
                backoff = backoff * 2 > HS_RETRY_MAX_MS ? HS_RETRY_MAX_MS : backoff * 2;
                continue;
            }
            need_hs = 0;
            backoff = HS_RETRY_MIN_MS;
        }

        /* Idle: watch for REKEY_REQ or a closed connection. */
        struct pollfd p = { .fd = ctx->ctrl_fd, .events = POLLIN };
        int r = poll(&p, 1, HS_POLL_SLICE_MS);
        if (r > 0) {
            uint8_t msg[HS_MSG_MAX], type;
            size_t len;
            int rc = recv_msg(ctx->ctrl_fd, ctx->cfg.timeout_ms, msg, &len, &type);
            if (rc != HS_OK || type != HS_MSG_REKEY_REQ) {
                if (rc == HS_OK)
                    hs_log("unexpected control message, reconnecting");
                close_ctrl(ctx);
            } else {
                atomic_store(&ctx->rekey_wanted, 1);
            }
        } else if (r < 0 && errno != EINTR) {
            close_ctrl(ctx);
        }
    }
}

static void responder_loop(handshake_ctx_t *ctx)
{
    int64_t last_req = 0;

    while (!atomic_load(&ctx->stop)) {
        if (open_listener(ctx) != HS_OK) {
            sleep_ms(ctx, HS_RETRY_MAX_MS);
            continue;
        }

        struct pollfd p[2];
        int n = 0;
        p[n++] = (struct pollfd){ .fd = ctx->listen_fd, .events = POLLIN };
        if (ctx->ctrl_fd >= 0)
            p[n++] = (struct pollfd){ .fd = ctx->ctrl_fd, .events = POLLIN };

        int r = poll(p, n, HS_POLL_SLICE_MS);
        if (r < 0 && errno != EINTR) {
            sleep_ms(ctx, 200);
            continue;
        }

        if (r > 0 && (p[0].revents & POLLIN)) {
            int fd = accept_one(ctx);
            if (fd >= 0) {
                close_ctrl(ctx);               /* a newer connection replaces the old */
                ctx->ctrl_fd = fd;
                continue;
            }
        }

        if (r > 0 && n == 2 && (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            uint8_t msg[HS_MSG_MAX], type;
            size_t len;
            int rc = recv_msg(ctx->ctrl_fd, ctx->cfg.timeout_ms, msg, &len, &type);
            if (rc == HS_OK && type == HS_MSG_HELLO)
                rc = responder_handshake(ctx, msg, len);
            else if (rc == HS_OK)
                rc = HS_ERR_PROTO;
            if (rc != HS_OK) {
                note_failure(ctx, rc);
                close_ctrl(ctx);
            }
        }

        /* Responder cannot start a handshake: it asks the initiator to. */
        if (atomic_load(&ctx->rekey_wanted) && ctx->ctrl_fd >= 0 &&
            atomic_load(&ctx->state) == HS_STATE_ESTABLISHED) {
            int64_t t = now_ms();
            if (t - last_req >= HS_REKEY_REQ_GAP) {
                uint8_t req[HS_HEADER_LEN];
                put_hdr(req, HS_MSG_REKEY_REQ, 0);
                if (send_msg(ctx->ctrl_fd, req, sizeof(req), ctx->cfg.timeout_ms) != HS_OK)
                    close_ctrl(ctx);
                last_req = t;
            }
            atomic_store(&ctx->rekey_wanted, 0);
        }
    }
}

static void *ctrl_thread(void *arg)
{
    handshake_ctx_t *ctx = arg;
    if (ctx->cfg.role == CRYPTO_ROLE_INITIATOR)
        initiator_loop(ctx);
    else
        responder_loop(ctx);
    return NULL;
}

int handshake_start(handshake_ctx_t *ctx)
{
    if (!ctx)
        return HS_ERR_PARAM;
    if (ctx->thread_running)
        return HS_ERR_STATE;
    atomic_store(&ctx->stop, 0);
    if (atomic_load(&ctx->state) != HS_STATE_ESTABLISHED)
        atomic_store(&ctx->state, HS_STATE_CONNECTING);
    if (pthread_create(&ctx->thread, NULL, ctrl_thread, ctx) != 0)
        return HS_ERR_GENERIC;
    ctx->thread_running = 1;
    return HS_OK;
}

void handshake_stop(handshake_ctx_t *ctx)
{
    if (!ctx || !ctx->thread_running)
        return;
    atomic_store(&ctx->stop, 1);
    pthread_join(ctx->thread, NULL);
    ctx->thread_running = 0;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

int handshake_init(handshake_ctx_t *ctx, const handshake_config_t *cfg)
{
    if (!ctx || !cfg)
        return HS_ERR_PARAM;
    if ((cfg->role != CRYPTO_ROLE_INITIATOR && cfg->role != CRYPTO_ROLE_RESPONDER) ||
        cfg->psk_len < 16 || cfg->psk_len > HS_PSK_MAX ||
        cfg->peer_ip.s_addr == 0)
        return HS_ERR_PARAM;

    memset(ctx, 0, sizeof(*ctx));
    ctx->cfg = *cfg;
    if (ctx->cfg.port == 0)
        ctx->cfg.port = HS_DEFAULT_PORT;
    if (ctx->cfg.timeout_ms <= 0)
        ctx->cfg.timeout_ms = HS_DEFAULT_TIMEOUT_MS;

    atomic_init(&ctx->active, 0);
    atomic_init(&ctx->has_previous, 0);
    atomic_init(&ctx->state, HS_STATE_IDLE);
    atomic_init(&ctx->rekey_wanted, 0);
    atomic_init(&ctx->stop, 0);
    ctx->ctrl_fd = -1;
    ctx->listen_fd = -1;
    return HS_OK;
}

void handshake_destroy(handshake_ctx_t *ctx)
{
    if (!ctx)
        return;
    handshake_stop(ctx);
    close_ctrl(ctx);
    if (ctx->listen_fd >= 0) {
        close(ctx->listen_fd);
        ctx->listen_fd = -1;
    }
    crypto_session_destroy(&ctx->sess[0]);
    crypto_session_destroy(&ctx->sess[1]);
    crypto_secure_zero(ctx->cfg.psk, sizeof(ctx->cfg.psk));
    atomic_store(&ctx->state, HS_STATE_IDLE);
}

/* ------------------------------------------------------------------ */
/* PSK loading                                                         */
/* ------------------------------------------------------------------ */

static int hex_val(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Text consisting only of hex digits (even length) is decoded as hex;
 * anything else is used as raw bytes. Minimum 16 bytes after decoding.
 */
int handshake_load_psk(const char *path, uint8_t *out, size_t cap, size_t *len)
{
    uint8_t raw[2 * HS_PSK_MAX + 8];
    struct stat st;

    if (!path || !out || !len)
        return HS_ERR_PARAM;
    if (stat(path, &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO)))
        hs_log("warning: %s is accessible by other users (chmod 600)", path);

    FILE *f = fopen(path, "rb");
    if (!f)
        return HS_ERR_GENERIC;
    size_t n = fread(raw, 1, sizeof(raw), f);
    int too_big = !feof(f);
    fclose(f);
    if (too_big)
        return HS_ERR_PARAM;

    while (n > 0 && (raw[n - 1] == '\n' || raw[n - 1] == '\r' ||
                     raw[n - 1] == ' '  || raw[n - 1] == '\t'))
        n--;

    int is_hex = (n % 2 == 0) && n > 0;
    for (size_t i = 0; is_hex && i < n; i++)
        if (hex_val(raw[i]) < 0)
            is_hex = 0;

    size_t outn = is_hex ? n / 2 : n;
    if (outn < 16 || outn > cap || outn > HS_PSK_MAX) {
        crypto_secure_zero(raw, sizeof(raw));
        return HS_ERR_PARAM;
    }
    if (is_hex)
        for (size_t i = 0; i < outn; i++)
            out[i] = (uint8_t)((hex_val(raw[2 * i]) << 4) | hex_val(raw[2 * i + 1]));
    else
        memcpy(out, raw, outn);

    *len = outn;
    crypto_secure_zero(raw, sizeof(raw));
    return HS_OK;
}

/* ------------------------------------------------------------------ */
/* Data-plane interface                                                */
/* ------------------------------------------------------------------ */

int handshake_is_established(const handshake_ctx_t *ctx)
{
    return ctx && atomic_load(&ctx->state) == HS_STATE_ESTABLISHED;
}

crypto_session_t *handshake_active_session(handshake_ctx_t *ctx)
{
    if (!handshake_is_established(ctx))
        return NULL;
    return &ctx->sess[atomic_load(&ctx->active)];
}

crypto_session_t *handshake_previous_session(handshake_ctx_t *ctx)
{
    if (!handshake_is_established(ctx) || !atomic_load(&ctx->has_previous))
        return NULL;
    return &ctx->sess[1 - atomic_load(&ctx->active)];
}

void handshake_request_rekey(handshake_ctx_t *ctx)
{
    if (ctx)
        atomic_store(&ctx->rekey_wanted, 1);
}

/* Only hides the old session; its memory is wiped at the next rekey or
 * in handshake_destroy(). Safe to call from the data-plane thread. */
void handshake_retire_previous(handshake_ctx_t *ctx)
{
    if (ctx)
        atomic_store(&ctx->has_previous, 0);
}
