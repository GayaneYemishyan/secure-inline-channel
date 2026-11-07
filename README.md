# Secure Inline Channel

A Linux prototype, written in C, of a **transparent inline encryption channel for TCP**. Two devices sit between two hosts and protect selected TCP/IPv4 flows without the hosts knowing:

```
pc1 ---- Device1 ======== Device2 ---- pc2
         (initiator)      (responder)
         encrypts  -->    decrypts
```

Each device intercepts packets with Linux **NFQUEUE**, encrypts or decrypts only the **TCP payload** with **AES-256-GCM**, and reinjects the packet. There is no tunnel, no UDP encapsulation and no custom outer header: the packet keeps its original IP and TCP headers, the payload grows by 24 bytes, and the checksums are recalculated.

> **Status: prototype / research code.** It has not been audited. Do not use it to protect real traffic.

## How it works

### Data plane (per packet)

| Direction | NFQUEUE | Action |
|---|---|---|
| host side -> peer device (`--lan`) | 0 (protect) | seal the payload in place |
| peer device -> host side (`--wan`) | 1 (unprotect) | verify, decrypt, restore the payload |

A protected payload looks like this:

```
ciphertext (n) | GCM tag (16) | counter (8, big-endian)     -> n + 24 bytes
```

- **Nonce** = 4-byte per-direction prefix || 8-byte packet counter. The counter is consumed before encryption, so a nonce is never reused with a key.
- **AAD** = source IP, destination IP, protocol, source port, destination port (13 bytes). TTL, IP ID, checksums and window are excluded on purpose, because they change in transit.
- **Replay protection**: 64-packet sliding window. The window only advances after the tag verifies, so forged packets cannot move it.
- **Pass-through**: packets with an empty payload (SYN, pure ACK, FIN, RST) are not encrypted.
- **MSS clamping**: SYN packets get their MSS lowered to `MTU - 40 - 24` to make room for the overhead.
- **Fail closed**: until a session is established, protected traffic is dropped. The iptables rules deliberately omit `--queue-bypass`, so if the program is not running, selected traffic is dropped rather than leaked.
- **Limits**: IP fragments are not supported. Soft rekey limit is 2^30 packets, hard limit 2^32.

### Control plane (handshake)

The handshake runs on its **own TCP connection** (default port 5555) between the two devices.

```
HELLO        initiator -> responder   nonce_i(32) | dh_pub_i(256)
HELLO_REPLY  responder -> initiator   nonce_r(32) | dh_pub_r(256) | mac_r(32)
FINISH       initiator -> responder   mac_i(32)
REKEY_REQ    responder -> initiator   (empty)

th    = SHA-256(HELLO || HELLO_REPLY-without-mac)
mac_r = HMAC-SHA256(psk, "RESP" || th)
mac_i = HMAC-SHA256(psk, "INIT" || th)
keys  = HKDF-SHA256(salt = th, ikm = DH secret)  -> 2 keys + 2 nonce prefixes
```

- **Key exchange**: ephemeral finite-field DH, RFC 7919 `ffdhe2048`. Peer keys are range-checked and fully validated.
- **Authentication**: pre-shared key (PSK). Role labels stop reflected MACs, fresh nonces stop handshake replay, and both DH public keys are in the transcript, so a man-in-the-middle without the PSK cannot forge either MAC.
- **Rekeying**: a new session is built in the inactive slot, then `active` flips atomically. The old session stays readable for a short grace period so in-flight packets still decrypt.
- **Resilience**: the control thread retries with exponential backoff (500 ms to 8 s). Only the configured peer IP may connect to the responder.

## Repository layout

```
include/
  crypto.h        AES-GCM, DH, HKDF, HMAC, replay window
  handshake.h     wire protocol, config, session slots
  packet.h        IPv4/TCP parsing, checksums, AAD, MSS clamp
src/
  main.c          entry point, NFQUEUE threads
  crypto.c        OpenSSL 3 EVP implementation
  handshake.c     control channel and control thread
  packet_handler.c  packet.h implementation + protect/unprotect logic
scripts/
  setup_netns.sh      four-namespace test topology
  setup_iptables.sh   NFQUEUE rules for each device
tests/            test_*.c (each built as its own program)
Makefile
```

## Requirements

- Linux with `nfnetlink_queue` and `xt_NFQUEUE` kernel modules
- Root privileges (NFQUEUE, iptables, network namespaces)
- GCC (or another C11 compiler), `make`
- **OpenSSL 3.x** (`libcrypto`): the code uses the OpenSSL 3 provider/EVP APIs
- `libnetfilter_queue` development headers
- `iptables`, `iproute2`, `ethtool`; optionally `iperf3` for testing

Debian/Ubuntu:

```bash
sudo apt install build-essential pkg-config libssl-dev libnetfilter-queue-dev \
                 iptables iproute2 ethtool iperf3
```

## Build

```bash
make              # builds ./secure-channel
make SAN=1        # AddressSanitizer + UBSan (run `make clean` first)
make test         # builds and runs tests/test_*.c
make psk          # creates psk.key (32 random bytes, hex) if missing
make clean
```

## Pre-shared key

Both devices need the **same** PSK, at least 16 bytes. `handshake_load_psk()` accepts raw bytes or hex text (trailing newline ignored).

```bash
make psk                     # writes psk.key with mode 600
scp psk.key device2:...      # copy over a secure channel
```

`*.key`, `*.psk` and `psk*` are in `.gitignore`. Never commit the key.

## Test topology

`scripts/setup_netns.sh` builds four network namespaces on one machine:

```
pc1 ---- dev1 ======== dev2 ---- pc2
10.0.1.10  10.0.1.1   10.0.12.2  10.0.2.1  10.0.2.10
                 10.0.12.1
```

```bash
sudo ./scripts/setup_netns.sh up       # create topology (MTU=1500 by default)
sudo ./scripts/setup_netns.sh ping     # baseline connectivity, before any NFQUEUE rule
sudo ./scripts/setup_netns.sh status
sudo ./scripts/setup_netns.sh down
```

Offloads (TSO/GSO/GRO, checksum offload) are disabled on every interface. With them on, the devices would see oversized packets and partial checksums, which breaks the checksum recalculation.

## Running

1. **Install the NFQUEUE rules** on each device with mirrored arguments:

   ```bash
   # Device1
   sudo ./scripts/setup_iptables.sh up --netns dev1 \
        --lan d1-lan --wan d1-wan \
        --local-net 10.0.1.0/24 --remote-net 10.0.2.0/24 --port 5201 --strict

   # Device2
   sudo ./scripts/setup_iptables.sh up --netns dev2 \
        --lan d2-lan --wan d2-wan \
        --local-net 10.0.2.0/24 --remote-net 10.0.1.0/24 --port 5201 --strict
   ```

   `--port N` limits protection to flows using that port; without it, all TCP between the two networks is protected. `--strict` drops everything else between the two networks, so nothing can cross unprotected. Omit `--netns` on real devices.

2. **Start `secure-channel`** on both devices (Device1 as initiator, Device2 as responder). Check `./secure-channel --help` for the exact options: role, local/peer IP, port, PSK file, MTU, queue numbers.

3. **Send traffic**:

   ```bash
   sudo ip netns exec pc2 iperf3 -s -p 5201
   sudo ip netns exec pc1 iperf3 -c 10.0.2.10 -p 5201
   ```

4. **Clean up**:

   ```bash
   sudo ./scripts/setup_iptables.sh down --netns dev1
   sudo ./scripts/setup_iptables.sh down --netns dev2
   sudo ./scripts/setup_netns.sh down
   ```

On the wire between the devices (e.g. `tcpdump -i d1-wan -X`) the TCP payload should be unreadable, while the IP and TCP headers are unchanged.

## Debugging notes

- The data plane logs counters via `packet_handler_log_stats()`: `sealed`, `opened`, `passed_clear`, `mss_clamped`, and drops split into `no_session`, `auth`, `replay`, `malformed`, `other`. A growing `no_session` or `auth` count usually points at the handshake or a PSK mismatch.
- Handshake errors are printed as `[handshake] ...`. `authentication failed` means a wrong PSK or an active attacker.
- If everything is dropped, check that the control connection (port 5555 between `10.0.12.1` and `10.0.12.2`) is not itself caught by the NFQUEUE rules. The rules are meant to match only traffic between the two LAN networks.
- Use `make SAN=1` to catch memory errors in the packet path.

## Known limitations

- IPv4 and TCP only; fragments are dropped.
- Packet length grows by 24 bytes, so MSS clamping is required, and non-SYN packets near the MTU may need a lower MTU on the host side.
- The PSK is static and shared; there is no certificate or identity handling.
- A session object is not thread-safe: run protect and unprotect from a single NFQUEUE thread or add locking.
- No ICMP "fragmentation needed" handling.

