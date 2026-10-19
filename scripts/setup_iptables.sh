#!/usr/bin/env bash
#
# Routes the selected TCP flows into the two NFQUEUEs used by secure-channel.
# Run once per device (Device1 and Device2), with mirrored arguments.
#
#   queue 0 (protect)   : packets arriving from the host side (--lan)
#   queue 1 (unprotect) : packets arriving from the peer device (--wan)
#
# Usage:
#   setup_iptables.sh up   --lan IF --wan IF --local-net CIDR --remote-net CIDR
#                          [--port N] [--strict] [--netns NAME]
#                          [--queue-protect N] [--queue-unprotect N]
#   setup_iptables.sh down [--netns NAME]
#   setup_iptables.sh status [--netns NAME]
#
# Selection: all TCP between local-net and remote-net, or, with --port N,
# only flows where the source or destination port is N.
# --strict: drop everything else between the two networks, so only the
# protected flows can cross (no ICMP/UDP/other-port leaks).
#
# NOTE: no --queue-bypass on purpose. If secure-channel is not running,
# selected traffic is dropped instead of leaking in the clear.

set -euo pipefail

CHAIN="SIC"
ACTION="${1:-}"
[[ $# -gt 0 ]] && shift

LAN="" WAN="" LOCAL_NET="" REMOTE_NET="" PORT="" STRICT=0 NETNS=""
Q_PROTECT=0 Q_UNPROTECT=1

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lan)              LAN="$2";        shift 2 ;;
        --wan)              WAN="$2";        shift 2 ;;
        --local-net)        LOCAL_NET="$2";  shift 2 ;;
        --remote-net)       REMOTE_NET="$2"; shift 2 ;;
        --port)             PORT="$2";       shift 2 ;;
        --queue-protect)    Q_PROTECT="$2";  shift 2 ;;
        --queue-unprotect)  Q_UNPROTECT="$2"; shift 2 ;;
        --netns)            NETNS="$2";      shift 2 ;;
        --strict)           STRICT=1;        shift ;;
        -h|--help)          usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "error: run as root (sudo)" >&2; exit 1; }
command -v iptables >/dev/null || { echo "error: iptables not found" >&2; exit 1; }

# Run iptables inside the namespace when --netns is given (test topology);
# on real devices leave it out.
NSX=()
[[ -n "$NETNS" ]] && NSX=(ip netns exec "$NETNS")
ipt() { "${NSX[@]}" iptables "$@"; }

is_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

remove_rules() {
    # idempotent: ignore errors when nothing is installed
    while ipt -D FORWARD -j "$CHAIN" 2>/dev/null; do :; done
    ipt -F "$CHAIN" 2>/dev/null || true
    ipt -X "$CHAIN" 2>/dev/null || true
}

# queue_rules <queue> <in-interface> <src-net> <dst-net>
queue_rules() {
    local q=$1 iface=$2 src=$3 dst=$4
    local base=(-A "$CHAIN" -i "$iface" -s "$src" -d "$dst" -p tcp)
    if [[ -n "$PORT" ]]; then
        ipt "${base[@]}" --dport "$PORT" -j NFQUEUE --queue-num "$q"
        ipt "${base[@]}" --sport "$PORT" -j NFQUEUE --queue-num "$q"
    else
        ipt "${base[@]}" -j NFQUEUE --queue-num "$q"
    fi
}

install_rules() {
    [[ -n "$LAN" && -n "$WAN" && -n "$LOCAL_NET" && -n "$REMOTE_NET" ]] || {
        echo "error: --lan, --wan, --local-net and --remote-net are required" >&2
        usage
    }
    [[ -z "$PORT" ]] || is_port "$PORT" || { echo "error: bad --port" >&2; exit 1; }
    [[ "$Q_PROTECT" != "$Q_UNPROTECT" ]] || { echo "error: queues must differ" >&2; exit 1; }

    # make sure the kernel side exists (best effort)
    modprobe nfnetlink_queue 2>/dev/null || true
    modprobe xt_NFQUEUE      2>/dev/null || true

    remove_rules
    ipt -N "$CHAIN"

    # host side -> peer device: encrypt
    queue_rules "$Q_PROTECT"   "$LAN" "$LOCAL_NET"  "$REMOTE_NET"
    # peer device -> host side: decrypt
    queue_rules "$Q_UNPROTECT" "$WAN" "$REMOTE_NET" "$LOCAL_NET"

    if (( STRICT )); then
        ipt -A "$CHAIN" -s "$LOCAL_NET"  -d "$REMOTE_NET" -j DROP
        ipt -A "$CHAIN" -s "$REMOTE_NET" -d "$LOCAL_NET"  -j DROP
    fi

    # evaluate before anything else in FORWARD
    ipt -I FORWARD 1 -j "$CHAIN"

    echo "rules installed${NETNS:+ in netns $NETNS}:"
    echo "  $LAN  ($LOCAL_NET -> $REMOTE_NET)  => NFQUEUE $Q_PROTECT   (protect)"
    echo "  $WAN  ($REMOTE_NET -> $LOCAL_NET)  => NFQUEUE $Q_UNPROTECT (unprotect)"
    echo "  selection: TCP${PORT:+ port $PORT}$( ((STRICT)) && echo ', strict' )"
}

case "$ACTION" in
    up)     install_rules ;;
    down)   remove_rules; echo "rules removed${NETNS:+ from netns $NETNS}" ;;
    status)
        ipt -L FORWARD -n --line-numbers | head -5
        echo
        ipt -L "$CHAIN" -n -v --line-numbers 2>/dev/null || echo "chain $CHAIN not installed"
        ;;
    *) usage ;;
esac
