#include "packet.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Parsing                                                             */
/* ------------------------------------------------------------------ */

int packet_parse(uint8_t *buf, size_t len, packet_view_t *v)
{
    if (!buf || !v)
        return PKT_ERR_PARAM;
    memset(v, 0, sizeof(*v));

    if (len < PACKET_MIN_IP_HLEN)
        return PKT_ERR_TRUNC;

    ip_hdr_t *ip = (ip_hdr_t *)buf;
    if (IP_VERSION(ip) != 4)
        return PKT_ERR_NOT_IPV4;

    size_t ihl = IP_HLEN(ip);
    if (ihl < PACKET_MIN_IP_HLEN)
        return PKT_ERR_BAD_LEN;
    if (ip->protocol != IPPROTO_TCP_NUM)
        return PKT_ERR_NOT_TCP;
    if (ntohs(ip->frag_off) & (IP_FLAG_MF | IP_FRAG_OFFMASK))
        return PKT_ERR_FRAGMENT;

    size_t tot = ntohs(ip->tot_len);
    if (tot > len)
        return PKT_ERR_TRUNC;               /* tot < len is fine: link padding */
    if (tot < ihl + PACKET_MIN_TCP_HLEN)
        return PKT_ERR_BAD_LEN;

    tcp_hdr_t *tcp = (tcp_hdr_t *)(buf + ihl);
    size_t thl = TCP_HLEN(tcp);
    if (thl < PACKET_MIN_TCP_HLEN || ihl + thl > tot)
        return PKT_ERR_BAD_LEN;

    v->buf         = buf;
    v->ip          = ip;
    v->tcp         = tcp;
    v->ip_hlen     = ihl;
    v->tcp_hlen    = thl;
    v->total_len   = tot;
    v->payload     = buf + ihl + thl;
    v->payload_len = tot - ihl - thl;
    return PKT_OK;
}

/* ------------------------------------------------------------------ */
/* Checksums                                                           */
/* ------------------------------------------------------------------ */

/*
 * Words are summed in native byte order. The one's-complement sum is
 * byte-order independent, so the folded result can be stored into the
 * header field as-is on any endianness.
 */
uint32_t checksum_partial(const void *data, size_t len, uint32_t sum)
{
    const uint8_t *p = data;
    while (len > 1) {
        uint16_t w;
        memcpy(&w, p, 2);
        sum += w;
        p += 2;
        len -= 2;
    }
    if (len) {                      /* odd trailing byte, zero-padded */
        uint16_t w = 0;
        memcpy(&w, p, 1);
        sum += w;
    }
    return sum;
}

uint16_t checksum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t packet_ip_checksum(const ip_hdr_t *ip)
{
    size_t ihl = IP_HLEN(ip);
    const uint8_t *p = (const uint8_t *)ip;
    if (ihl < PACKET_MIN_IP_HLEN)
        return 0;
    /* skip the checksum field (bytes 10-11) */
    uint32_t sum = checksum_partial(p, 10, 0);
    sum = checksum_partial(p + 12, ihl - 12, sum);
    return checksum_fold(sum);
}

uint16_t packet_tcp_checksum(const ip_hdr_t *ip,
                             const uint8_t *tcp_seg, size_t tcp_len)
{
    if (tcp_len < PACKET_MIN_TCP_HLEN)
        return 0;

    /* pseudo-header: saddr, daddr, 0, protocol, tcp length */
    uint8_t ph[4] = { 0, IPPROTO_TCP_NUM,
                      (uint8_t)(tcp_len >> 8), (uint8_t)(tcp_len & 0xFF) };
    uint32_t sum = checksum_partial(&ip->saddr, 8, 0);
    sum = checksum_partial(ph, sizeof(ph), sum);

    /* TCP header + payload, skipping the checksum field (bytes 16-17) */
    sum = checksum_partial(tcp_seg, 16, sum);
    sum = checksum_partial(tcp_seg + 18, tcp_len - 18, sum);
    return checksum_fold(sum);
}

int packet_recalc_checksums(const packet_view_t *v)
{
    if (!v || !v->ip || !v->tcp)
        return PKT_ERR_PARAM;
    v->ip->check  = packet_ip_checksum(v->ip);
    v->tcp->check = packet_tcp_checksum(v->ip, (const uint8_t *)v->tcp,
                                        v->total_len - v->ip_hlen);
    return PKT_OK;
}

/* ------------------------------------------------------------------ */
/* Payload rewriting                                                   */
/* ------------------------------------------------------------------ */

int packet_replace_payload(packet_view_t *v, size_t buf_cap,
                           const uint8_t *new_payload, size_t new_len)
{
    if (!v || !v->buf || (!new_payload && new_len))
        return PKT_ERR_PARAM;

    size_t hdrs  = v->ip_hlen + v->tcp_hlen;
    size_t total = hdrs + new_len;
    if (total > PACKET_MAX_LEN || total > buf_cap)
        return PKT_ERR_NOSPACE;

    if (new_len && new_payload != v->payload)
        memmove(v->payload, new_payload, new_len);

    v->ip->tot_len  = htons((uint16_t)total);
    v->total_len    = total;
    v->payload_len  = new_len;
    return packet_recalc_checksums(v);
}

/* ------------------------------------------------------------------ */
/* AAD and MSS clamping                                                */
/* ------------------------------------------------------------------ */

int packet_build_aad(const packet_view_t *v, uint8_t aad[PACKET_AAD_LEN])
{
    if (!v || !v->ip || !v->tcp || !aad)
        return PKT_ERR_PARAM;
    memcpy(aad,     &v->ip->saddr, 4);
    memcpy(aad + 4, &v->ip->daddr, 4);
    aad[8] = v->ip->protocol;
    memcpy(aad + 9,  &v->tcp->sport, 2);    /* network order, as on the wire */
    memcpy(aad + 11, &v->tcp->dport, 2);
    return PKT_OK;
}

int packet_clamp_mss(const packet_view_t *v, uint16_t max_mss)
{
    if (!v || !v->tcp)
        return PKT_ERR_PARAM;
    if (!(v->tcp->flags & TCP_FLAG_SYN))
        return 0;

    uint8_t *p   = (uint8_t *)v->tcp + PACKET_MIN_TCP_HLEN;
    uint8_t *end = (uint8_t *)v->tcp + v->tcp_hlen;

    while (p < end) {
        uint8_t kind = p[0];
        if (kind == TCP_OPT_EOL)
            break;
        if (kind == TCP_OPT_NOP) {
            p++;
            continue;
        }
        if (p + 1 >= end)
            break;
        uint8_t olen = p[1];
        if (olen < 2 || p + olen > end)
            break;                              /* malformed option list */
        if (kind == TCP_OPT_MSS && olen == 4) {
            uint16_t mss = (uint16_t)((p[2] << 8) | p[3]);
            if (mss <= max_mss)
                return 0;
            p[2] = (uint8_t)(max_mss >> 8);
            p[3] = (uint8_t)(max_mss & 0xFF);
            v->tcp->check = packet_tcp_checksum(v->ip, (const uint8_t *)v->tcp,
                                                v->total_len - v->ip_hlen);
            return 1;
        }
        p += olen;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Packet handler                                                      */
/* ------------------------------------------------------------------ */

void packet_handler_init(packet_handler_t *h, handshake_ctx_t *hs, unsigned mtu)
{
    memset(h, 0, sizeof(*h));
    h->hs = hs;
    if (mtu < 200)
        mtu = 1500;
    /* IP(20) + TCP(20) + MSS + overhead must fit in the MTU. */
    h->max_mss = (uint16_t)(mtu - 40 - CRYPTO_OVERHEAD);
}

static ph_verdict_t drop(uint64_t *counter)
{
    (*counter)++;
    return PH_DROP;
}

/* Local host -> peer device: encrypt the payload in place. */
static ph_verdict_t do_protect(packet_handler_t *h, uint8_t *buf, size_t buf_cap,
                               size_t len, size_t *out_len)
{
    packet_view_t v;
    uint8_t aad[PACKET_AAD_LEN];
    int modified = 0;

    if (packet_parse(buf, len, &v) != PKT_OK)
        return drop(&h->stats.dropped_malformed);

    crypto_session_t *s = handshake_active_session(h->hs);
    if (!s)
        return drop(&h->stats.dropped_no_session);

    /* Every protected packet grows by CRYPTO_OVERHEAD: shrink the MSS. */
    if (v.tcp->flags & TCP_FLAG_SYN) {
        int m = packet_clamp_mss(&v, h->max_mss);
        if (m < 0)
            return drop(&h->stats.dropped_malformed);
        if (m > 0) {
            modified = 1;
            h->stats.mss_clamped++;
        }
    }

    /* Nothing to encrypt: SYN, pure ACK, FIN, RST pass in the clear. */
    if (v.payload_len == 0) {
        h->stats.passed_clear++;
        if (modified) {
            *out_len = v.total_len;
            return PH_ACCEPT_MODIFIED;
        }
        return PH_ACCEPT;
    }

    size_t hdrs    = v.ip_hlen + v.tcp_hlen;
    size_t new_len = v.payload_len + CRYPTO_OVERHEAD;
    if (hdrs + new_len > PACKET_MAX_LEN || hdrs + new_len > buf_cap)
        return drop(&h->stats.dropped_other);

    if (packet_build_aad(&v, aad) != PKT_OK)
        return drop(&h->stats.dropped_other);

    /* Seal in place: ciphertext || tag || counter, written over the payload. */
    size_t sealed = 0;
    int rc = crypto_session_seal(s, aad, sizeof(aad),
                                 v.payload, v.payload_len,
                                 v.payload, new_len, &sealed);
    if (crypto_session_needs_rekey(s) || rc == CRYPTO_ERR_EXHAUSTED)
        handshake_request_rekey(h->hs);
    if (rc != CRYPTO_OK)
        return drop(&h->stats.dropped_other);

    /* Payload already in place: only lengths and checksums change. */
    if (packet_replace_payload(&v, buf_cap, v.payload, sealed) != PKT_OK)
        return drop(&h->stats.dropped_other);

    h->stats.sealed++;
    *out_len = v.total_len;
    return PH_ACCEPT_MODIFIED;
}

/* Peer device -> local host: verify, decrypt, restore the packet. */
static ph_verdict_t do_unprotect(packet_handler_t *h, uint8_t *buf, size_t buf_cap,
                                 size_t len, size_t *out_len)
{
    packet_view_t v;
    uint8_t aad[PACKET_AAD_LEN];

    if (packet_parse(buf, len, &v) != PKT_OK)
        return drop(&h->stats.dropped_malformed);

    crypto_session_t *s = handshake_active_session(h->hs);
    if (!s)
        return drop(&h->stats.dropped_no_session);

    /* Empty-payload packets are never encrypted by the peer. */
    if (v.payload_len == 0) {
        h->stats.passed_clear++;
        return PH_ACCEPT;
    }
    if (v.payload_len < CRYPTO_OVERHEAD)
        return drop(&h->stats.dropped_malformed);

    if (packet_build_aad(&v, aad) != PKT_OK)
        return drop(&h->stats.dropped_other);

    /*
     * Open into scratch (not in place): a failed attempt must leave the
     * packet intact so the previous session can still be tried after a rekey.
     */
    size_t pt_len = 0;
    int rc = crypto_session_open(s, aad, sizeof(aad), v.payload, v.payload_len,
                                 h->scratch, sizeof(h->scratch), &pt_len);
    if (rc == CRYPTO_ERR_AUTH || rc == CRYPTO_ERR_REPLAY) {
        crypto_session_t *prev = handshake_previous_session(h->hs);
        if (prev)
            rc = crypto_session_open(prev, aad, sizeof(aad),
                                     v.payload, v.payload_len,
                                     h->scratch, sizeof(h->scratch), &pt_len);
    }

    switch (rc) {
    case CRYPTO_OK:
        break;
    case CRYPTO_ERR_AUTH:
        return drop(&h->stats.dropped_auth);
    case CRYPTO_ERR_REPLAY:
        return drop(&h->stats.dropped_replay);
    case CRYPTO_ERR_SHORT:
    case CRYPTO_ERR_PARAM:
        return drop(&h->stats.dropped_malformed);
    default:
        return drop(&h->stats.dropped_other);
    }

    if (packet_replace_payload(&v, buf_cap, h->scratch, pt_len) != PKT_OK) {
        crypto_secure_zero(h->scratch, pt_len);
        return drop(&h->stats.dropped_other);
    }
    crypto_secure_zero(h->scratch, pt_len);

    h->stats.opened++;
    *out_len = v.total_len;
    return PH_ACCEPT_MODIFIED;
}

ph_verdict_t packet_handler_process(packet_handler_t *h, ph_dir_t dir,
                                    uint8_t *buf, size_t buf_cap, size_t len,
                                    size_t *out_len)
{
    if (!h || !h->hs || !buf || !out_len || len > buf_cap)
        return PH_DROP;
    *out_len = len;
    return dir == PH_PROTECT ? do_protect(h, buf, buf_cap, len, out_len)
                             : do_unprotect(h, buf, buf_cap, len, out_len);
}

void packet_handler_log_stats(const packet_handler_t *h)
{
    const packet_handler_stats_t *s = &h->stats;
    fprintf(stderr,
            "[packet] sealed=%llu opened=%llu clear=%llu mss_clamped=%llu | "
            "drop: no_session=%llu auth=%llu replay=%llu malformed=%llu other=%llu\n",
            (unsigned long long)s->sealed, (unsigned long long)s->opened,
            (unsigned long long)s->passed_clear, (unsigned long long)s->mss_clamped,
            (unsigned long long)s->dropped_no_session,
            (unsigned long long)s->dropped_auth,
            (unsigned long long)s->dropped_replay,
            (unsigned long long)s->dropped_malformed,
            (unsigned long long)s->dropped_other);
}
