#ifndef PACKET_H
#define PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define PACKET_MAX_LEN       65535
#define PACKET_MIN_IP_HLEN   20
#define PACKET_MAX_IP_HLEN   60
#define PACKET_MIN_TCP_HLEN  20
#define PACKET_MAX_TCP_HLEN  60

/* AAD = saddr(4) | daddr(4) | protocol(1) | sport(2) | dport(2) */
#define PACKET_AAD_LEN       13

#define IPPROTO_TCP_NUM      6

/* IP flags / fragment field (host order after ntohs) */
#define IP_FLAG_MF           0x2000
#define IP_FRAG_OFFMASK      0x1FFF

/* TCP flags */
#define TCP_FLAG_FIN         0x01
#define TCP_FLAG_SYN         0x02
#define TCP_FLAG_RST         0x04
#define TCP_FLAG_PSH         0x08
#define TCP_FLAG_ACK         0x10
#define TCP_FLAG_URG         0x20

/* TCP option kinds */
#define TCP_OPT_EOL          0
#define TCP_OPT_NOP          1
#define TCP_OPT_MSS          2

/* ------------------------------------------------------------------ */
/* Header structs (all multi-byte fields are in network byte order)   */
/* ------------------------------------------------------------------ */

typedef struct __attribute__((packed)) {
    uint8_t  ver_ihl;      /* version (high 4 bits) | IHL in 32-bit words */
    uint8_t  tos;
    uint16_t tot_len;      /* header + payload, bytes                     */
    uint16_t id;
    uint16_t frag_off;     /* flags (3 bits) | fragment offset (13 bits)  */
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /* options (if IHL > 5) follow */
} ip_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  doff_res;     /* data offset (high 4 bits, 32-bit words) | reserved */
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
    /* options (if data offset > 5) follow */
} tcp_hdr_t;

#define IP_VERSION(ip)   ((ip)->ver_ihl >> 4)
#define IP_HLEN(ip)      ((size_t)((ip)->ver_ihl & 0x0F) * 4)
#define TCP_HLEN(tcp)    ((size_t)((tcp)->doff_res >> 4) * 4)

/* ------------------------------------------------------------------ */
/* Return codes                                                        */
/* ------------------------------------------------------------------ */

typedef enum {
    PKT_OK            =  0,
    PKT_ERR_PARAM     = -1,   /* NULL / bad argument                      */
    PKT_ERR_TRUNC     = -2,   /* buffer shorter than the headers claim    */
    PKT_ERR_NOT_IPV4  = -3,
    PKT_ERR_NOT_TCP   = -4,
    PKT_ERR_FRAGMENT  = -5,   /* IP fragment: unsupported, pass or drop   */
    PKT_ERR_BAD_LEN   = -6,   /* inconsistent IHL / data offset / tot_len */
    PKT_ERR_NOSPACE   = -7    /* new payload does not fit in the buffer   */
} packet_status_t;

/* ------------------------------------------------------------------ */
/* Parsed view                                                         */
/* ------------------------------------------------------------------ */

/*
 * Pointers into the caller's buffer; nothing is copied.
 * Invalidated if the buffer is freed or moved.
 * total_len comes from ip->tot_len, NOT from the buffer length,
 * because the buffer may contain trailing link-layer padding.
 */
typedef struct {
    uint8_t   *buf;
    ip_hdr_t  *ip;
    tcp_hdr_t *tcp;
    uint8_t   *payload;       /* points just past the TCP header          */
    size_t     ip_hlen;
    size_t     tcp_hlen;
    size_t     total_len;     /* IP total length                          */
    size_t     payload_len;   /* total_len - ip_hlen - tcp_hlen           */
} packet_view_t;

/* ------------------------------------------------------------------ */
/* Parsing                                                             */
/* ------------------------------------------------------------------ */

/*
 * Validate and parse an IPv4/TCP packet starting at the IP header
 * (as delivered by NFQUEUE). Checks: version 4, IHL >= 5, protocol TCP,
 * not a fragment, data offset >= 5, headers fit, tot_len <= len.
 * Does not verify checksums.
 */
int packet_parse(uint8_t *buf, size_t len, packet_view_t *v);

/* ------------------------------------------------------------------ */
/* Checksums                                                           */
/* ------------------------------------------------------------------ */

/* One's-complement sum helpers (exposed for unit tests). */
uint32_t checksum_partial(const void *data, size_t len, uint32_t sum);
uint16_t checksum_fold(uint32_t sum);

/* IP header checksum (check field treated as zero). Network order. */
uint16_t packet_ip_checksum(const ip_hdr_t *ip);

/*
 * TCP checksum over pseudo-header + TCP header + payload
 * (check field treated as zero). Network order.
 * tcp_len = TCP header + payload bytes.
 */
uint16_t packet_tcp_checksum(const ip_hdr_t *ip,
                             const uint8_t *tcp_seg, size_t tcp_len);

/* Recompute and store both checksums in place. Returns PKT_OK. */
int packet_recalc_checksums(const packet_view_t *v);

/* ------------------------------------------------------------------ */
/* Payload rewriting                                                   */
/* ------------------------------------------------------------------ */

/*
 * Replace the TCP payload with new_payload (new_len bytes; may be longer
 * or shorter). Updates ip->tot_len, refreshes the view, recalculates both
 * checksums. new_payload may alias v->payload (memmove is used).
 * buf_cap is the capacity of v->buf; PKT_ERR_NOSPACE if it won't fit or
 * the result would exceed PACKET_MAX_LEN.
 */
int packet_replace_payload(packet_view_t *v, size_t buf_cap,
                           const uint8_t *new_payload, size_t new_len);

/* ------------------------------------------------------------------ */
/* AAD and MSS helpers                                                 */
/* ------------------------------------------------------------------ */

/*
 * Build the AES-GCM additional authenticated data from header fields that
 * never change between Device1 and Device2: src/dst IP, protocol,
 * src/dst port. Both devices call this on the packet they hold, so the
 * result is identical on both sides. TTL, IP ID, checksums, and window are
 * excluded on purpose.
 */
int packet_build_aad(const packet_view_t *v, uint8_t aad[PACKET_AAD_LEN]);

/*
 * If the packet is a SYN carrying an MSS option larger than max_mss,
 * lower it to max_mss and fix the TCP checksum. Needed because every
 * protected packet grows by CRYPTO_OVERHEAD bytes.
 * Returns 1 if modified, 0 if nothing changed, <0 on error.
 */
int packet_clamp_mss(const packet_view_t *v, uint16_t max_mss);

#endif /* PACKET_H */