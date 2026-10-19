#!/usr/bin/env bash
#
# Builds the four-node test topology with network namespaces:
#
#   pc1 ---- dev1 ======== dev2 ---- pc2
#   10.0.1.10  10.0.1.1   10.0.12.2  10.0.2.1  10.0.2.10
#                  10.0.12.1
#
#   pc1-eth0 <-> d1-lan   (10.0.1.0/24)   host side of Device1
#   d1-wan   <-> d2-wan   (10.0.12.0/24)  inter-device link (protected + control)
#   d2-lan   <-> pc2-eth0 (10.0.2.0/24)   host side of Device2
#
# Usage: sudo ./scripts/setup_netns.sh {up|down|status|ping}
# Env:   MTU=1500 (applied to every interface)

set -euo pipefail

MTU="${MTU:-1500}"
NAMESPACES=(pc1 dev1 dev2 pc2)

need_root() {
    [[ $EUID -eq 0 ]] || { echo "error: run as root (sudo)" >&2; exit 1; }
}

nsx() {                         # nsx <namespace> <command...>
    local ns=$1; shift
    ip netns exec "$ns" "$@"
}

teardown() {
    # Deleting a namespace also removes the veth ends inside it,
    # and with them the peer ends in the other namespaces.
    for ns in "${NAMESPACES[@]}"; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

# configure <ns> <ifname> <cidr>
configure_if() {
    local ns=$1 ifname=$2 cidr=$3
    nsx "$ns" ip addr add "$cidr" dev "$ifname"
    nsx "$ns" ip link set "$ifname" mtu "$MTU" up
}

# Offloads must be off: with TSO/GSO/GRO the devices would see oversized
# packets, and partial checksums would break the checksum recalculation.
disable_offloads() {
    local ns=$1 ifname=$2
    nsx "$ns" ethtool -K "$ifname" rx off tx off sg off tso off gso off gro off \
        >/dev/null 2>&1 || true
}

setup() {
    teardown

    for ns in "${NAMESPACES[@]}"; do
        ip netns add "$ns"
        nsx "$ns" ip link set lo up
        nsx "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1   # keep captures clean
    done

    # veth pairs: create in the root namespace, then move each end
    ip link add pc1-eth0 type veth peer name d1-lan
    ip link set pc1-eth0 netns pc1
    ip link set d1-lan   netns dev1

    ip link add d1-wan type veth peer name d2-wan
    ip link set d1-wan netns dev1
    ip link set d2-wan netns dev2

    ip link add d2-lan type veth peer name pc2-eth0
    ip link set d2-lan   netns dev2
    ip link set pc2-eth0 netns pc2

    # addresses
    configure_if pc1  pc1-eth0 10.0.1.10/24
    configure_if dev1 d1-lan   10.0.1.1/24
    configure_if dev1 d1-wan   10.0.12.1/24
    configure_if dev2 d2-wan   10.0.12.2/24
    configure_if dev2 d2-lan   10.0.2.1/24
    configure_if pc2  pc2-eth0 10.0.2.10/24

    # routing: hosts use their device as gateway, devices route to each other
    nsx pc1  ip route add default via 10.0.1.1
    nsx pc2  ip route add default via 10.0.2.1
    nsx dev1 ip route add 10.0.2.0/24 via 10.0.12.2
    nsx dev2 ip route add 10.0.1.0/24 via 10.0.12.1

    for ns in dev1 dev2; do
        nsx "$ns" sysctl -qw net.ipv4.ip_forward=1
        nsx "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
        nsx "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
    done

    # offloads off on every interface
    disable_offloads pc1  pc1-eth0
    disable_offloads dev1 d1-lan
    disable_offloads dev1 d1-wan
    disable_offloads dev2 d2-wan
    disable_offloads dev2 d2-lan
    disable_offloads pc2  pc2-eth0

    echo "topology ready (MTU $MTU):"
    echo "  pc1 10.0.1.10 -> dev1 [10.0.1.1 | 10.0.12.1] => dev2 [10.0.12.2 | 10.0.2.1] -> pc2 10.0.2.10"
}

status() {
    for ns in "${NAMESPACES[@]}"; do
        if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
            echo "== $ns =="
            nsx "$ns" ip -br addr show | grep -v '^lo'
            nsx "$ns" ip route show
        else
            echo "== $ns == (missing)"
        fi
    done
}

# Baseline connectivity check, before any NFQUEUE rule is loaded.
ping_test() {
    local ok=0
    check() {                   # check <ns> <target> <label>
        if nsx "$1" ping -c 2 -W 1 -q "$2" >/dev/null 2>&1; then
            printf '  [ ok ] %s\n' "$3"
        else
            printf '  [FAIL] %s\n' "$3"; ok=1
        fi
    }
    check pc1  10.0.1.1  "pc1  -> dev1 (host link)"
    check dev1 10.0.12.2 "dev1 -> dev2 (inter-device link)"
    check pc2  10.0.2.1  "pc2  -> dev2 (host link)"
    check pc1  10.0.2.10 "pc1  -> pc2  (end to end, via both devices)"
    return $ok
}

need_root
case "${1:-}" in
    up)     setup ;;
    down)   teardown; echo "topology removed" ;;
    status) status ;;
    ping)   ping_test ;;
    *)      echo "usage: $0 {up|down|status|ping}" >&2; exit 1 ;;
esac
