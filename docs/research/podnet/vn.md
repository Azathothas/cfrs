# The `vn` kit (version 3): what podnet takes from it

Sources (read only, untrusted):
`att/3389cc8a-vn-v3/vn/` (README.md 220 lines, NOTES.md 50, THIRD_PARTY.md
31, LICENSE 14, Cargo.toml 8, Cargo.lock 974 (109 crates), crates/vn/ 5 172
lines of Rust, csup/csup.c 1 408, test/*.c 156, prove.sh 525, scripts/*.sh
72, vn.sh 5, vn-run.sh 18). Nothing in `bin-prebuilt/` and no script was run.
No private key or token is in the kit (grep for key, token and 32-byte hex or
base64 patterns: no match outside `Cargo.lock` checksums).

Compared with `/workspace/cfrs` at `3bed023`, `study/mwan-field.md` and
`study/architecture.md`.

Sizes: XS <= 2 h, S <= 1 day, M = 2-4 days, L = 1-2 weeks.

---

## 0. Verdict in five lines

* vn is a prototype of two things that cfrs already has in a more complete
  form: a pod with its own kernel stack behind a userspace router (cfrs
  `pod-netns` netns backend, no root) and a seccomp user-notify supervisor
  (cfrs `pod-netns` seccomp backend, 7 architectures, async).
* Port no file as is. Take five ideas (section 3): a gateway-to-host-loopback
  map, generic UDP in the netns backend, three seccomp details for W-F2, a
  kind for ICMP datagram sockets, and (optional) a veth + `AF_PACKET` wire
  for hosts with user namespaces but no `/dev/net/tun`.
* Drop `csup.c`, `boringtun`, the root kernel mode, the DoH resolver, the
  name table, the dialer and the WireGuard test binaries.
* vn is not the multi-WAN router of `mwan-field.md`: it has one carrier,
  no health check, no weights, no failover.
* Several README/NOTES claims do not hold for the shipped source (section 1.8).

---

## 1. What vn is

### 1.1 Purpose

"A virtual network with virtual NAT on a host whose only way out is TCP
`CONNECT` through a broker" (README:3-6). The broker accepts `CONNECT
name:port` and refuses `CONNECT address:port` (README:56-60). A guest gets
DNS answers with virtual addresses (10.7.1.1-10.7.1.254), and the router
dials the name behind each virtual address.

### 1.2 Files

| File | Lines | Role |
| --- | --- | --- |
| `crates/vn/src/router.rs` | 927 | Kernel-mode router: Ethernet frames in, smoltcp `Interface` (`any_ip`), TCP/UDP flow tables, DNS and ICMP answers |
| `crates/vn/src/guest.rs` | 737 | User-mode "guest socket service": Unix socket server, ops `T U D I L Q P`, one thread per connection |
| `crates/vn/src/carrier.rs` | 600 | Carriers: `Direct`, `Connector` (HTTP `CONNECT` over TCP or Unix socket), `LocalDatagram`, `Composite`; proxy URL parse, base64 |
| `crates/vn/src/main.rs` | 370 | CLI `vn up`, `vn run`, `vn carrier`; namespace setup with `ip`, `sysctl` |
| `crates/vn/src/wg.rs` | 320 | smoltcp device on queues, ICMP echo helpers, X25519 key files (via boringtun) |
| `crates/vn/src/tap.rs` | 319 | TAP create inside a named netns (fork + `setns`, fd back by `SCM_RIGHTS`), `SIOCSIFHWADDR` |
| `crates/vn/src/resolve.rs` | 317 | DoH JSON client (rustls) through the `Connector`, one worker thread |
| `crates/vn/src/bin/vn-wg-guest.rs` | 310 | Test client: boringtun initiator + smoltcp, sends N bytes and one echo |
| `crates/vn/src/wire.rs` | 276 | `Wire::Tap` or `Wire::Veth` (veth by `ip link`, `AF_PACKET` raw socket, `ethtool -K` offloads off) |
| `crates/vn/src/names.rs` | 242 | Name table (254 addresses), DNS question parse, A reply build |
| `crates/vn/src/bin/vn-wg-peer.rs` | 242 | Test server: boringtun responder + smoltcp, counts received bytes |
| `crates/vn/src/dialer.rs` | 147 | One worker thread that opens carrier streams |
| `crates/vn/src/device.rs` | 139 | smoltcp `Device` on the wire (Ethernet medium), pre-read frame queue |
| `crates/vn/src/frame.rs` | 134 | u16 big-endian length records on a byte stream |
| `crates/vn/src/egress.rs` | 70 | Traits `Stream`, `Carrier`; keys `StreamKey`, `DatagramKey` |
| `crates/vn/src/lib.rs` | 22 | Constants: gateway 10.7.0.1, guest 10.7.0.2, resolver 10.7.0.53 |
| `csup/csup.c` | 1 408 | C seccomp user-notify supervisor (`vn-csup`) |
| `test/static-guest.c` | 121 | Static C guest: UDP DNS, TCP connect, ICMP echo |
| `test/static-listener.c` | 35 | Static C guest: bind, listen, connect to itself, accept |
| `prove.sh` | 525 | End-to-end "claims" script (root, `ip`, `wg`, `ethtool`, `python3`, `gcc`) |

### 1.3 Kernel mode ("kernel wire", `vn up` as root)

```text
guest process (ip netns exec vn CMD)
  -> kernel stack of netns "vn" (10.7.0.2/24, default via 10.7.0.1, IPv6 off)
  -> vn0: TAP in the netns (fd handed back by SCM_RIGHTS)  | or veth vn0 <-> vn0h + AF_PACKET on vn0h
  -> Router::admit_frames (router.rs:273)
       ICMP echo to 10.7.0.1      -> answer_echo (router.rs:514), built by hand
       UDP to port 53             -> answer_dns (router.rs:430): NameTable + AsyncResolver
       TCP SYN                    -> new smoltcp listen socket on the dst port (router.rs:331)
       UDP other                  -> smoltcp UDP socket bound on the dst port + DatagramFlow (router.rs:381)
       other IP protocols         -> dropped (router.rs:327)
  -> smoltcp Interface (Ethernet medium, any_ip, 10.7.0.1/24)
  -> pump_tcp (router.rs:541): at SynReceived, Dialer::request(StreamKey{src,dst,name})
  -> Dialer worker thread (dialer.rs:67) -> Carrier::open_stream / open_datagram
       Composite: dst == 10.7.0.1 -> TCP 127.0.0.1:port, or UDP LocalDatagram 127.0.0.1:port
                  else            -> Connector (CONNECT name:port; no name = refused)
                                     or Direct (TCP to the name or the address)
  -> PipeStream (non-blocking TCP or Unix stream); UDP = u16 records on that stream
```

The main loop polls the wire fd with a 2 ms timeout (main.rs:255-278).
Limits: 64 TCP flows, 64 UDP flows, 64 KiB per flow (router.rs:43-50),
idle reap 300 s.

### 1.4 User mode ("user wire", default for a non-root user)

```text
CMD under vn-csup (seccomp user notify, no privileges)
  socket(AF_INET)  -> csup injects one end of a socketpair (ADDFD SEND)
  connect(TCP)     -> csup writes 'T'+dst on a pre-opened Unix connection to the
                      guest server, reads a status byte, installs that connection
                      at the guest fd (ADDFD SETFD): no relay in csup
  sendto(UDP)      -> csup preads the payload from /proc/PID/mem, frames
                      [dst4, port2, payload] on a pre-opened 'U' connection
  replies          -> csup writes each record as one datagram into the pair
  recvfrom         -> not trapped (the kernel copies from the pair)
GuestServer (guest.rs) on $XDG_RUNTIME_DIR/guest.sock or /tmp/vn-UID/guest.sock
  'T' -> Carrier::open_stream, then pump() (1 ms sleep loop, guest.rs:567)
  'U' -> port 53 answered from the name table (blocking DoH), else one carrier
         channel per destination (guest.rs:237)
  'I' -> each echo answered here, for any destination (guest.rs:491)
  'L'/'Q'/'P' -> listener registry (guest.rs:514-562)
```

### 1.5 Carriers and WAN types

One carrier for the process, chosen at start (main.rs:78-82, 177-181):
`Connector` when a proxy is named (`VN_PROXY_SOCKET` Unix path, or
`HTTPS_PROXY`/`https_proxy`/`HTTP_PROXY`/`http_proxy` over TCP, Basic auth
only), else `Direct`. `Composite` puts the gateway address on the host
loopback. The `Connector` refuses ports other than 80, 443, 8080, 8443
(main.rs:40, carrier.rs:390-395). No SOCKS, no chain, no rule, no second
uplink.

Datagram flows ride the same byte pipes: `Direct::open_datagram` and
`Connector::open_datagram` open a TCP stream to the destination name:port
(carrier.rs:176-179, 450-454) and write u16 records on it. Only the
gateway's `LocalDatagram` turns records back into real UDP (carrier.rs:192-264).

### 1.6 WireGuard use

* `vn-wg-peer` and `vn-wg-guest` are test programs, not tools. The peer
  accepts one peer key, answers echoes and counts the bytes of one TCP
  stream on its inner smoltcp host. The guest sends a handshake, one echo
  and N bytes, then exits. Both use `boringtun::noise::Tunn` for the Noise
  state machine and a timer tick each 200 ms.
* In both proofs the WireGuard peer is on the same host: the guest's
  endpoint is 10.7.0.1:41820, which `Composite` maps to 127.0.0.1:41820
  (prove.sh:227-233 and 456-468). No proof reaches a remote WireGuard
  endpoint.
* Keys are 64 hex characters in `*.key`/`*.pub` files (wg.rs:236-260), not
  the base64 form of `wg`.

### 1.7 The C supervisor `csup.c`

Mechanism: seccomp user notification only. No ptrace, no `LD_PRELOAD`, no
namespaces.

* `prctl(PR_SET_NO_NEW_PRIVS)`, then `seccomp(SECCOMP_SET_MODE_FILTER,
  SECCOMP_FILTER_FLAG_NEW_LISTENER)` with a BPF program that returns
  `SECCOMP_RET_USER_NOTIF` for 17 x86-64 syscall numbers: close, dup, dup2,
  dup3, socket, connect, accept, accept4, sendto, sendmsg, sendmmsg, bind,
  listen, getsockname, getpeername, setsockopt, getsockopt (csup.c:54-77,
  1361-1386). Any other architecture value returns `ALLOW` (csup.c:1368-1369):
  i386 compat calls are not seen. `io_uring` is not trapped.
* `SECCOMP_IOCTL_NOTIF_RECV`/`SEND`/`ADDFD` (flags `SEND` and `SETFD`),
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, `pread` of `/proc/PID/mem` (read only,
  csup.c:288-311), `PR_SET_DUMPABLE 1` to keep that file readable.
* The filter is installed on the supervisor itself, before `fork()`
  (csup.c:1354-1404). The supervisor must therefore never make a trapped
  call: it opens 296 Unix connections and 32 Unix listeners before the
  filter (csup.c:1256-1352) and never closes a descriptor.
* One notification at a time, with a blocking read of the broker status
  inside `connect` (csup.c:682): one slow `CONNECT` stops every socket call
  of every thread of the guest.
* Answers it cannot give: `getsockname`/`getpeername` return 0 and leave the
  buffer as it was (csup.c:1026-1042); IP-level `setsockopt`/`getsockopt`
  return 0 with no effect (csup.c:1043-1057); `recvfrom` gives the AF_UNIX
  source, not the IPv4 one (not trapped); netlink sockets become a dead
  datagram pair (csup.c:518-545; the `R_*` request codes at csup.c:114-118
  and the "unfiltered process" have no code).

### 1.8 Claims and what the source shows

| Claim | Where | Source | Result |
| --- | --- | --- | --- |
| A guest "keeps UDP, kernel WireGuard and every other IP protocol" | README:4-6 | Protocols other than 1/6/17 are dropped (router.rs:327); ICMP only to the gateway; remote UDP is carried as records inside a TCP `CONNECT` to the same name:port, which no UDP service reads | Holds only for UDP that ends on the host (gateway = 127.0.0.1) |
| Kernel WireGuard handshake, ICMP and 100 000 bytes "over the virtual network" | README:178-179 | Peer endpoint 10.7.0.1 = host 127.0.0.1 (prove.sh:465) | Proves a loopback path, not WireGuard over a TCP-only egress |
| Static binaries are served as dynamic ones | README:20-22 | Seccomp interception, x86-64 only | Holds in principle; cfrs already does it on 7 architectures |
| A guest listener receives inbound flows (user wire) | README:190, NOTES:19 | csup sends `Q` plus a path that `handle_listen` never reads (guest.rs:514-541, csup.c:883-901); csup never sends `P`; `connect_listener` refuses an empty path (guest.rs:191) | Cannot hold with this source |
| Pool of "192 UDP + 8 ICMP + 96 bare connections" | NOTES:44-46 | `pool_take_bare`/`pool_take_udp`/`pool_take_icmp` never set `used` (csup.c:254-278; only the listener pool sets it, csup.c:902). A second TCP `connect` writes its header into the first, live, connection; after one dead slot is retired (`fd = -1`), each later `connect` gets `ECONNREFUSED`. All UDP sockets share the first `U` connection | One TCP connection per guest works; more break |
| The seccomp call is made "through inline assembly" | NOTES:28-30 | `syscall(SYS_seccomp, ...)`; no `asm` in csup.c | Not in the source |
| "no library is preloaded" | main.rs:200-203 | README:91-104 and scripts set `VN_SHIM=.../vnshim.so`; no preload source or file exists | Document drift |
| DoH "on the carrier's own path" past a broker that refuses addresses | resolve.rs:1-6 | `RESOLVER_HOST = "1.1.1.1"`, so the request is `CONNECT 1.1.1.1:443` (main.rs:38, resolve.rs:55). The cfrs measured sandbox proxy resets exactly this (`docs/target-environment.md:23`) | Fails on the broker it describes |
| Prebuilt binaries | README:65 | `file`: dynamically linked glibc PIE, not static. `strings bin-prebuilt/vn-csup` has `CSUP_DEBUG`, `csup: supervisor starting`, `csup: connect fd=%d`, which csup.c does not have | The binaries are not built from this source |

What `prove.sh` measures. Capable host (root): `/proc/modules` has
`wireguard`; `ip link add type wireguard` works; `/dev/kvm` answers
`KVM_GET_API_VERSION` (unrelated to vn); a UDP send to 1.1.1.1:443 fails;
the guest has 10.7.0.2/24 and a default via 10.7.0.1; ping to 10.7.0.1; a
UDP DNS query to 10.7.0.53 gets an answer; HTTP GET to example.com:80 through
the broker (one retry); kernel WireGuard to a host-side `wgpeer` at
127.0.0.1:41820, 3 pings, 100 000 bytes. Host with `CapEff=0`: `/dev/net/tun`
does not open; uid != 0; UDP send fails; the guest socket appears; a static
guest (one DNS query, one TCP connect to port 443 with plain HTTP, one echo
to the gateway); Python DNS; Python HTTPS to example.com (one retry); Python
ICMP to the gateway; Python listener; userspace WireGuard to `vn-wg-peer` on
127.0.0.1. Each user clause makes at most one TCP connection per guest
process, which is why the pool defect does not show.

### 1.9 Privileges

| Part | Needs |
| --- | --- |
| `vn up` kernel mode (default for euid 0) | root: `ip netns add` (writes `/var/run/netns`), `setns`, `TUNSETIFF`, `SIOCSIFHWADDR`, `ip link add ... type veth`, `AF_PACKET` (CAP_NET_RAW), `ethtool -K`, `sysctl`; binaries `ip`, `ethtool` |
| `vn run` kernel mode | root (`ip netns exec`) |
| `vn up` user mode | nothing; binds a Unix socket |
| `vn run` user mode | `vn-csup`: seccomp user notify with `ADDFD` (Linux >= 5.9; `ADDFD_FLAG_SEND` >= 5.14), `NO_NEW_PRIVS`; x86-64 only |
| `vn-wg-peer` | nothing (UDP bind on 127.0.0.1) |
| `prove.sh` | root for the kernel clauses; `ip`, `wg`, `ethtool`, `python3`, `gcc -static` |

### 1.10 Dependencies and licence

* Direct: `libc 0.2`, `rustls 0.23` (`ring`, `std`, `tls12`),
  `rustls-pki-types 1`, `webpki-roots 0.26`, `smoltcp 0.14`, `boringtun 0.6`
  (no default features). 109 crates in `Cargo.lock`.
* `boringtun 0.6.0` brings `ring 0.16.20` (beside `ring 0.17.14`),
  `x25519-dalek 2.0.0-rc.3`, `curve25519-dalek 4.0.0-rc.3`, `nix 0.25.1`,
  `parking_lot`, `tracing`, `ip_network_table`.
* Licence: vn is 0BSD (LICENSE): compatible with podnet 0BSD; no notice is
  required. The crate licences are all in the cfrs `deny.toml` allow list
  (`boringtun` BSD-3-Clause adds a notice line to `THIRD_PARTY_NOTICES.md`).
* Blockers for podnet (to confirm with `cargo deny` and a cross build):
  `curve25519-dalek < 4.1.3` has RUSTSEC-2024-0344 and `ring < 0.17.12` has
  RUSTSEC-2025-0009, and cfrs has `ignore = []`; `ring 0.16` has no support
  for riscv64, powerpc64le and loongarch64, three of the eight release
  targets in `deny.toml`. cfrs already has its own WireGuard on `ring 0.17`
  (`src/warp/wg.rs`, own BLAKE2s). cfrs pins `smoltcp =0.12.0` for the MSRV
  (Cargo.toml:89); vn needs 0.14.

### 1.11 Other defects (do not copy)

* The guest socket and its directory are made with default modes
  (main.rs:186-188, guest.rs:96-102): each local user can use the egress,
  and op `P` makes the server connect to any Unix path that the vn user can
  reach (a confused deputy). cfrs has `listen::private_dir` (issue 306).
* csup makes predictable `$TMPDIR/vn-sup-PID-PORT.sock` names and unlinks
  them first (csup.c:1321-1352).
* The DoH request puts the guest's DNS name in the request line with no
  encoding (resolve.rs:46); labels are `from_utf8_lossy` bytes (names.rs:114),
  so CR/LF from a guest goes into the HTTP request.
* The kernel router drops a DNS query when the name is not resolved yet and
  waits for the guest to retry (router.rs:451-462): the first lookup of a
  name costs one resolver timeout (glibc: 5 s). The real address is never
  given to the guest, so the lookup is not needed for the `Connector`.
* One dialer thread opens every flow in series, with a 20 s connect limit
  (dialer.rs:67-81, carrier.rs:26): one slow destination stops all new flows.
* UDP flows that share a destination port share one smoltcp socket; the
  pump of flow A drops the datagrams of flow B (`continue` at router.rs:688).
* Name table: 254 addresses, never reused (names.rs:17-19, 49-51).
* Debug output in the data path: `vn: pump forwarded N bytes` for each read
  (guest.rs:584), `csup: connect val=...` for each connect (csup.c:1211-1216).
* `vn.sh` and `vn-run.sh` at the root use `$(dirname "$0")/..`, which is the
  parent of the kit (copies of `scripts/`).

---

## 2. Module-by-module comparison with cfrs

| vn | cfrs piece | Who covers it better | Note |
| --- | --- | --- | --- |
| Kernel mode: named root netns + TAP (`main.rs`, `tap.rs`) | `crates/pod-netns/src/netns.rs` (1 199): user + net namespace, TUN `eth0`, smoltcp, no root, no `ip` binary; `raw.rs` (436): TUN fd of raw IP to WARP | cfrs | cfrs needs no root. vn's only extra: a long-lived namespace that later programs join (`ip netns exec`), which is W-F1 `--join` in `mwan-field.md` |
| `wire.rs` veth + `AF_PACKET` | none (no `veth`, `AF_PACKET`, `IFF_TAP` or `medium-ethernet` in cfrs) | vn (idea only) | A wire with no `/dev/net/tun`. vn needs root and `ip`/`ethtool`; podnet could do it inside the pod's own user namespace (P5) |
| `router.rs` TCP: listen socket per SYN, dial at `SynReceived`, abort on failure | `netns.rs` `HeldSyn` (issue 190): the SYN waits until the upstream dial ends; a failed dial gets a RST; a tokio task per dial | cfrs | vn completes the handshake to the guest, then aborts: the guest sees a reset after `connect()` returned 0 |
| `router.rs` UDP flows (`admit_udp`, `pump_datagrams`) | netns backend: UDP 53 only (`answer_dns`, netns.rs:666) | vn (idea only) | cfrs netns pods have no generic UDP. smoltcp 0.12 already has `UdpMetadata::local_address` (the comment at netns.rs:662-665 is out of date). P2 |
| `router.rs` ICMP echo to the gateway | netns: smoltcp answers echoes to its own address; raw backend carries real ICMP | equal | - |
| `Composite` + `LocalDatagram` (gateway = host loopback) | netns backend sends a gateway destination to the upstream as `10.66.255.254:port`; seccomp sends loopback direct (issue 80) | vn (idea only) | A netns pod cannot reach a host service. P1 |
| `names.rs` + `answer_dns` | `fakedns.rs` (198.18.0.0/15 = 131 072 addresses, fake IPv6 in seccomp, `--map` pins), `dns.rs` (pointer-safe parser) | cfrs | - |
| `resolve.rs` (DoH JSON at the IP 1.1.1.1) | `src/resolve.rs` (591): pins, system resolver, DoH by IP at two operators with NXDOMAIN fallback, DoH by name through the proxy (issue 259) | cfrs | vn's resolver fails on the measured proxy |
| `carrier.rs` `Connector`/`Direct` | `src/egress.rs` (1 707): HTTP `CONNECT`, SOCKS5/5h, `unix:`, `+exec`, `NO_PROXY`, RFC 8305 dial; `proxy_auth.rs`; `pod-netns/src/upstream.rs` (1 040): chains, rules, tailnet, SOCKS5 UDP ASSOCIATE and UDP in the stream (`CMD_UDP_IN_STREAM` 0x83) | cfrs | vn's datagram carrier writes records to a TCP peer that is not a UDP relay; cfrs's 0x83 frames go to a server that sends real UDP (`warp proxy`/`up`, pods) |
| `frame.rs` | `src/vnet/framing.rs` (IP packets), `upstream.rs` `write_udp_frame`/`read_udp_frame` (same u16 big-endian format) | cfrs | One vn test is new: an empty datagram survives (section 3.6) |
| `dialer.rs` (one worker thread) | tokio task per dial (`netns.rs` `dialing`, seccomp `within_timeout`) | cfrs | - |
| `egress.rs` traits `Carrier`/`Stream` | proposed `Dialer`/`Datagrams`/`Target` (`architecture.md` 4.3) | equal shape | `StreamKey.destination_name` = `Target::Name`; confirms the design; nothing to port |
| `guest.rs` guest socket service | `warp up` socket (SOCKS5 + UDP in the stream) + `warp exec` pods; `pod-netns --serve` front door (`frontdoor.rs`) | cfrs | cfrs has private directories, async I/O, rules |
| `csup.c` | `crates/pod-netns/src/seccomp.rs` (1 900): filter on a helper thread + fork (the supervisor is not filtered), 7 `AUDIT_ARCH` values, `io_uring_*` refused, `recvfrom`/`recvmsg` source addresses written back (`inbox.rs`, issue 305), memory writes by `/proc/PID/mem` or `process_vm_writev`, `SO_ERROR` (issue 302), `MAX_TRACKED_FDS`, inbound listeners (issue 69) | cfrs | Three csup details are better (section 3.3): it keeps a TCP entry after `connect`; it tracks `dup`/`dup2`/`dup3` with a reference count; it hands the service connection to the guest with `ADDFD SETFD`, so no relay copies bytes |
| csup ICMP sockets (`K_ICMP`) | `handle_socket` ignores the protocol argument (seccomp.rs:948-953): `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` becomes a UDP datagram socket | vn (idea only) | A ping socket in a seccomp pod is relayed as UDP. P4 |
| `wg.rs` + boringtun + `vn-wg-*` | `src/warp/wg.rs` (1 078): own Noise IKpsk2 initiator, BLAKE2s, `ring` AEAD, WARP reserved bytes, keepalive; a responder exists only in its tests (wg.rs:884) | cfrs (initiator); neither has a usable responder | A userspace WireGuard responder is the "generic WireGuard peer" of `architecture.md` step F. Write it on cfrs `wg.rs`, not on boringtun |
| `wg.rs` `InnerDevice` | `src/vnet/device.rs` `LinkDevice` (in-process queue pair), `src/warp/ip.rs` `WarpStack` | cfrs | - |
| `vn carrier` report | `cfrs doctor`, `pod-netns doctor --json`, `cfrs net doctor`, `preflight` | cfrs | - |
| src/vnet switch, shim, policy, record, tailscale front door | none in vn | cfrs | vn has no multi-host link, no `LD_PRELOAD`, no policy, no capture, no tailnet |
| src/warp tun, export, MASQUE | none in vn | cfrs | vn has no way to send real UDP out of a TCP-only host; cfrs does it with WARP MASQUE over HTTP/2 through the proxy |
| src/race.rs | none in vn | cfrs | - |

### 2.1 vn and the multi-WAN router of `mwan-field.md`

No. The study's mode A needs an `Uplink` list (N WARP identities, proxy
chains, direct), weights, sticky UDP, TCP health probes with K/R counts,
failover, fail-closed, per-uplink status. vn has one carrier, picked once
at start; `Composite` is a fixed local/upstream split; the dialer is serial;
no probe, no weight, no state. vn is a front end of mode A (it takes flows
off a guest kernel wire), and cfrs already has better front ends (SOCKS/HTTP
front doors, both pod backends, `warp up`). The only router-relevant ideas
are P1 (a router that serves netns pods must give them the host) and P2
(UDP for netns pods, so a router can balance their UDP flows too).

---

## 3. Recommendation

### 3.1 Port list

Port ideas, not files. All items are Rust in today's `crates/pod-netns`
(proposed `podnet-netns`), need no root, add no dependency and keep one
static musl binary.

| # | Item | vn source of the idea | Target | Size | Tests |
| --- | --- | --- | --- | --- | --- |
| P4 | ICMP datagram sockets get a kind in the seccomp backend: an echo to the pod gateway is answered by the supervisor; other destinations get `EACCES` (or, later, go through a WARP upstream). Today they are relayed as UDP | csup.c:561-563, 618-625; guest.rs:491-511 (echo reply build) | `podnet-netns` seccomp (`handle_socket`, `handle_sendto`) | XS (about 60 lines) | C test in `tests/seccomp.rs`: `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`, echo to the gateway answered, echo to 192.0.2.1 refused with a defined errno (from `test/static-guest.c` lines 99-118) |
| P3 | Fold into W-F2 (`mwan-field.md` rank 1): (a) keep the TCP entry after `connect` and answer IP-level `setsockopt`/`getsockopt` from it (csup keeps `swapped` entries); (b) track duplicates with a reference count, and trap `fcntl(F_DUPFD, F_DUPFD_CLOEXEC)` too (csup misses it; Rust `try_clone` uses it), or key by socket inode as W-F2 proposes; (c) fd handoff: when the upstream is a plain fd (Unix socket or TCP to an HTTP/SOCKS proxy, no TLS, no in-process framing) and the handshake is done, install it at the child's fd with `ADDFD SETFD` and drop the relay task. With a TCP upstream, `TCP_NODELAY` and `getsockopt` then work natively | csup.c:632-700 (connect + `install_at`), 932-996 (`handle_dup`), 1043-1057 | `podnet-netns` seccomp | (a)(b) inside W-F2 (M); (c) S (about 150 lines) | W-F2 tests; plus: after handoff, `setsockopt(TCP_NODELAY)` = 0 on a TCP-proxy upstream; a `dup2` of a UDP socket still sends to the right destination; no relay task stays after handoff (byte counters: a decision for the owner, section 5) |
| P1 | Netns backend: the gateway address maps to the host loopback, opt in (`--host-gateway`, as slirp4netns `10.0.2.2`): TCP to `TUN_GW:port` connects `127.0.0.1:port` on the host; UDP to `TUN_GW:port` (not 53) goes to a host UDP socket | carrier.rs:186-312 (`LocalDatagram`, `Composite`) | `podnet-netns` netns (`accept_flows` target choice, UDP path of P2) | S (about 120 lines) | netns test: a pod reaches a host `127.0.0.1` listener through the gateway when the flag is on and is refused when off; UDP echo through the gateway (after P2) |
| P2 | Netns backend: generic UDP. A flow table keyed by (src, dst) with an idle reap and a cap; datagrams taken from the TUN before smoltcp (as `answer_dns` does) and replies built as packets with the addresses swapped (no smoltcp UDP socket per port, which is vn's defect); carried by the existing upstream UDP in the stream (0x83), else SOCKS5 UDP ASSOCIATE; names from `FakeDns` sent as names (as seccomp does) | router.rs:381-427, 654-755 (flow table, reap) | `podnet-netns` netns | M (about 350 lines) | `netns_backend_relays_udp` and `netns_backend_relays_udp_in_the_stream` (mirrors of the seccomp tests); a test with two flows to one destination port that loses no datagram; reap after idle |
| P5 | Optional: a netns wire with no `/dev/net/tun`. In the child's user + net namespace: an rtnetlink `RTM_NEWLINK` veth pair (no `ip`), an `AF_PACKET` socket bound to one end, its fd sent to the parent (as the TUN fd is today); smoltcp Ethernet medium (feature `medium-ethernet`) with ARP; RX checksums not verified (or `PACKET_AUXDATA`), so no `ethtool` is needed. `auto` then picks netns where user namespaces work but the TUN does not | wire.rs:70-153, device.rs, tap.rs:80-119 (fd back by `SCM_RIGHTS`) | `podnet-netns` netns (new `veth.rs`) + doctor row | M (about 500 lines) | doctor probe; a netns test that runs with `/dev/net/tun` hidden (a private mount namespace with an empty `/dev/net`) and proxies a static and a dynamic binary; skip where user namespaces cannot bring `lo` up (the ubuntu runner, `docs/target-environment.md`) |

### 3.2 Rewrite (later, not a port)

* A userspace WireGuard responder ("podnet wg serve": a WireGuard endpoint
  with no `CAP_NET_ADMIN`, its inner flows sent to podnet dialers) is what
  `vn-wg-peer` hints at. Write it on cfrs `src/warp/wg.rs`: add the responder
  half (the test function `respond` at wg.rs:884 is the seed), cookie
  replies, several peers, timers; reuse `vnet::device::LinkDevice` and
  smoltcp. Crate: `podnet-warp` now, an own adapter crate after step F.
  Size L. Owner question 3.

### 3.3 Drop

| vn part | Reason |
| --- | --- |
| `csup/csup.c` | C, x86-64 only, the supervisor filters itself (pool, never closes a descriptor), pool and listener defects (1.8), no `recvfrom` source, no `io_uring` block; cfrs `seccomp.rs` is the superset. A second C binary also breaks "one static binary" |
| `guest.rs` | Thread per connection, 1 ms sleep loops, open socket permissions, op `P` confused deputy; cfrs `warp up` + pods cover it |
| Kernel mode (`main.rs` `up`/`run`/`configure_guest`, `tap.rs`) | Needs root and `ip`/`ethtool`/`sysctl`; cfrs netns backend does it with no root |
| `resolve.rs` | DoH at an IP literal (refused by the measured proxy), no encoding, serial, one TLS connection per lookup; cfrs `resolve.rs` is better |
| `names.rs` | 254 addresses; cfrs `fakedns.rs` has 131 072 and IPv6 |
| `dialer.rs` | Serial worker; cfrs uses a task per dial and `HeldSyn` |
| `carrier.rs` `Connector`/`Direct`, `frame.rs` | cfrs `egress.rs`, `upstream.rs`, `vnet/framing.rs` are supersets; vn's UDP-over-TCP-to-destination has no far end |
| `wg.rs`, `vn-wg-guest.rs`, `vn-wg-peer.rs`, `boringtun` | Test harness; `boringtun 0.6` brings `ring 0.16` (three release targets fail, to confirm) and `curve25519-dalek 4.0.0-rc.3` (advisory); cfrs has its own WireGuard |
| `prove.sh`, `vn.sh`, `vn-run.sh`, `scripts/` | Root, `python3`, `gcc`, `wg`; proves loopback paths only; cfrs tests and `live.yml` cover the same questions |
| `bin-prebuilt/` | Dynamic glibc, not built from this source; never run |

### 3.4 Order

1. P4 (XS): a bug fix; any time, before or after the file splits.
2. P3 with W-F2 (M + S): rank 1 of `mwan-field.md`; do it after the split of
   `seccomp.rs` (`architecture.md` step B5) or in the same series.
3. P1 (S) and P2 (M): after the split of `netns.rs` (step B5). P2 ends the
   choice "seccomp for UDP, netns for correct socket calls" (`mwan-field.md`
   question 3, W-F2b): with P2, `warp exec` can take netns first.
4. P5 (M): only after a host measurement (section 5, question 4).
5. WireGuard responder (L): after step F (traits), as a new adapter.

Total for P1-P5 without the W-F2 base: about 1 200 lines of code and
500 lines of tests.

### 3.5 Conflicts with "one static musl binary, no root"

* vn as shipped conflicts with both: four binaries (three Rust, one C),
  dynamic glibc prebuilts, a root kernel mode, `ip`/`ethtool`/`sysctl` at
  run time, `python3`/`gcc`/`wg` for its proof.
* The port list has no conflict: Rust inside `podnet-netns`, no external
  binary (rtnetlink in place of `ip`, no `ethtool`), no new crate, no root.
  P5 needs unprivileged user namespaces (the same need as the netns backend
  today). The smoltcp feature `medium-ethernet` (P5) adds code size only.

### 3.6 Tests to bring along

* From `frame.rs`: `an_empty_datagram_survives` as a test of
  `upstream::write_udp_frame`/`read_udp_frame` (a zero-length UDP datagram
  is valid). The other frame and name tests exist in cfrs
  (`vnet/framing.rs`, `vnet/dns.rs`, `pod-netns/src/dns.rs`).
* From `test/static-guest.c`: the ICMP part, for P4.
* New tests per item: in the table of 3.1.
* Not needed: `static-listener.c` (cfrs has `seccomp_backend_accepts_inbound`,
  `seccomp_inbound_wakes_epoll_and_accept_does_not_block_the_child`),
  static/dynamic binary tests (cfrs has both backends), `prove.sh`.

---

## 4. Facts checked in cfrs for this comparison

* `crates/pod-netns/src/seccomp.rs:60-81`: trapped calls (socket, recvfrom,
  recvmsg, connect, sendto, sendmsg, sendmmsg, bind, getsockname,
  getpeername, setsockopt, getsockopt, io_uring_setup/enter/register, close,
  listen, accept, accept4); `:122-144` seven `AUDIT_ARCH` values;
  `:580-666` filter on a helper thread and fork; `:939-1004` `handle_socket`
  does not read `a[2]` (protocol); `:1056` `map.remove(&fd)` after a TCP
  connect (the F2 defect).
* `crates/pod-netns/src/netns.rs:20-35` TUN /31, fake IPs 198.18.0.0/15;
  `:396-437` `HeldSyn`; `:659-675` UDP 53 only; `:1049-1060` `unshare`
  (net, else user + net).
* `crates/pod-netns/src/upstream.rs:580-655` UDP in the stream (0x83), u16
  frames.
* `~/.cargo/registry/src/*/smoltcp-0.12.0/src/socket/udp.rs:25`:
  `UdpMetadata::local_address` exists in the pinned smoltcp.
* `src/warp/wg.rs:1-10, 258-384, 884`: own WireGuard initiator; a test-only
  responder.
* `deny.toml`: eight musl targets, `ignore = []`, licence allow list.
* `docs/target-environment.md:23`: the measured proxy resets `CONNECT
  1.1.1.1:443`.

## 5. Questions for the owner

1. P1: the gateway-to-host-loopback map lets a netns pod reach every host
   service on 127.0.0.1. Opt in (`--host-gateway`), as podman does, or on by
   default, as slirp4netns does?
2. P3(c) fd handoff: after the handoff the supervisor sees no bytes of that
   connection (no byte counts, no idle timeout, no per-flow log). Take it
   for Unix-socket upstreams only, for all plain-fd upstreams, or not at all?
3. A userspace WireGuard responder ("podnet wg serve"): wanted, and before
   or after Tailscale/Firezone?
4. P5 (veth + `AF_PACKET` with no `/dev/net/tun`): is there a target host
   with user namespaces but no TUN? If none is known, drop P5.
5. With P2 done, may `warp exec` take the netns backend first (correct
   socket calls and UDP), and keep seccomp for hosts with no user
   namespaces?
6. Keep any vn names (`vn`, 10.7.0.0/24) for compatibility? This study
   assumes no: podnet keeps its own addresses (10.66.255.254/31, 198.18/15).
