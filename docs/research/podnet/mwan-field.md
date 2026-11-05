# mwan, the lab kit and the beta.12 field report: what podnet needs

Sources (read only):

* `att/58330911-mwan-standalone/mwan/`: README.md (121 lines), main.go (423),
  example.json (20), BUILD.md (9). The `mwan` binary was not run.
* `att/562a2c99-cfrs-standalone/cfrs/`: README.md (42), setup-wans.sh (109),
  docs/FR-multi-wan-aggregation.md (86), docs/masque-session-tcp-blackhole.md
  (69), docs/warp-tun-rp-filter-strict.md (62),
  docs/warp-export-kernel-wg-data-path-degrades.md (55). `state/` was not opened.
* `att/522011b9-cfrs-field-report/`: cfrs-field-report.md (155),
  cfrs-field-evidence-seccomp-rst.log (38).
* Code: /workspace/cfrs at `3bed023` (main, 4 commits after v0.3.0-beta.12
  `3b6e173`; none of the 4 touch the files below).

Sizes: XS <= 2 h, S <= 1 day, M = 2-4 days, L = 1-2 weeks.

---

## 1. mwan

### 1.1 What it does

`mwan` is a Go "director" (stdlib only, `CGO_ENABLED=0`). It forwards no
packet. It programs the kernel of one namespace with `ip` and `nft`
subprocesses and checks the links in a loop.

* WAN types: any interface that already exists. Two kinds in the code:
  an on-link TUN (no `gateway`: cfrs `warp tun`, wireguard) and a veth or
  ethernet link with a `gateway` (next hop via). mwan creates no interface,
  no tunnel.
* Per WAN: `ip route replace default [via GW] dev IFACE table T`
  (main.go:270-277), and a rule `fwmark T lookup T prio 5000`
  (main.go:278-280). The mark is the table id.
* Aggregate: `ip route replace default table AGG nexthop [via GW] dev IF
  weight W ...` with one nexthop for each healthy WAN (main.go:293-311).
  Balancing is kernel ECMP, per flow (the lab sets
  `fib_multipath_hash_policy=1`, the L4 hash). One TCP flow uses one lane.
* Clients: `ip rule add from SRC lookup AGG|T prio 9000` (main.go:316-334).
  An empty `wan` = the aggregate; a WAN name = pinned to that table.
* Egress NAT: nft table `ip sn-mwan`, chain postrouting, `oifname IF
  masquerade` for each WAN (main.go:358-376). Reason (README:84-89): the
  multipath hash runs before the source port exists and again after, so a
  flow can be sourced on WAN 1 and leave on WAN 2.
* Health (main.go:201-247): `icmp` = `ping -m T -c 1 -W 3 TARGET`;
  `tcp` = a TCP dial with `SO_MARK=T`, 3 s timeout, to `TARGET:check_port`.
  `misses_to_fail` misses = down; one success = up.
* Failover: the loop runs `checkAll` + `apply` each `interval_s`; a down
  link leaves the nexthop list. Kill switch: no healthy link = delete the
  aggregate default (main.go:306-309).
* Modes: `watch` (loop + HTTP `/status` JSON, `/metrics` text on
  `metrics`), `apply` (check once, program, exit), `check` (apply, print,
  exit 1 when all down), `status` (print).

### 1.2 Config schema (example.json)

| Key | Type | Default | Use |
| --- | --- | --- | --- |
| `netns` | string | `""`/`host` = current | wraps each `ip` call in `ip netns exec NETNS` |
| `metrics` | string | none | listen address of `/status`, `/metrics` (flag `--metrics` overrides) |
| `interval_s` | int | 5 | loop period |
| `check_target` | string | `1.1.1.1` | default target of each WAN |
| `check_mode` | `icmp`\|`tcp` | `icmp` | probe kind |
| `check_port` | int | 443 | TCP probe port |
| `misses_to_fail` | int | 3 | misses before down |
| `aggregate_table` | int | 51000 | ECMP table id |
| `wans[]` | `{name, iface, table, weight=1, gateway?, check_target?}` | | one per WAN |
| `clients[]` | `{source: CIDR, wan: ""\|NAME}` | | source rules |

example.json: `warp-a`/`cfrsA`/10010, `wg-masque`/`hwan1`/10020 via
10.66.0.2, `vpngate`/`hwan2`/10030 via 10.66.0.6; clients 10.77.1.0/24 to
the aggregate, 10.77.2.0/24 pinned to warp-a, 10.77.3.0/24 to wg-masque.

### 1.3 Privileges

Everything except `status` needs root or CAP_NET_ADMIN: `ip route`/`ip rule`
(netlink writes), `nft`, `SO_MARK` (CAP_NET_ADMIN), `ping -m` (CAP_NET_ADMIN).
It needs `ip`, `nft`, `ping` on PATH, kernel policy routing, multipath
routes and nf_tables NAT. Nothing of it runs in the podnet target
environment (no CAP_NET_ADMIN, proxy-only egress). Only the HTTP status
server is userspace.

### 1.4 Defects in main.go (podnet must not copy them)

| # | Defect | Where |
| --- | --- | --- |
| D1 | The kill switch leaks. With the aggregate default deleted, the rule `from SRC lookup AGG` finds no route and the kernel goes on to the next rule (main, with the host default). Clients leave by the host path. Use `unreachable default` (or `blackhole`) in the table, or a second rule `from SRC unreachable`. | main.go:306-309 |
| D2 | Pinned clients have no failover and no kill switch: when the link goes down, the kernel drops `default dev IF` from table T and the rule falls through to main. | main.go:270-277, 324-333 |
| D3 | Each interval deletes then adds each rule: a window with no rule each 5 s (traffic goes to main). | main.go:278-280, 323-333, 339-353 |
| D4 | Health checks run in the namespace of the mwan process, not in `netns`: only `ip` is wrapped; `ping` and the Go dialer are not. | main.go:209-226 vs 173-179 |
| D5 | The TCP probe never closes its connection (`_, err = dialer.Dial(...)`): one socket per WAN per interval until GC. | main.go:219 |
| D6 | TCP mode has no RTT (`parseRtt("tcp")` = 0). | main.go:220, 240 |
| D7 | README documents per-WAN `check_mode`, `check_port`, `misses_to_fail`; the struct has only `check_target`. | README:64-67 vs main.go:32-39 |
| D8 | `--mode status` prints a new process's defaults (`up: true`, `unchecked`), not the state of a running `watch`. | main.go:155-156 |
| D9 | Client rules at prio 9000 send traffic between local subnets to the aggregate (no `lookup main suppress_prefixlength 0` before them). | main.go:332 |
| D10 | No rise count: one good probe puts a link back. IPv4 only. | main.go:239-245 |
| D11 | README says the build needs a `vendor/` dir; BUILD.md says no dependency. | README:104, BUILD.md:5 |

### 1.5 What the experiment proved and did not prove

Proved (FR text, not measured here):

* Several cfrs `warp tun` instances with distinct identities run on one host
  at the same time; per-flow ECMP over 3 tunnels (2 WARP + 1 VPNGate)
  gave 175-290 Mbps (FR:48-49).
* ICMP health checks lie for a cfrs MASQUE session that carries ICMP and
  UDP but no TCP; a TCP connect check sees it (README:92-94).
* ECMP over tunnels needs egress masquerade, rp_filter 0 on each WAN, and a
  `via` for veth WANs.
* WG over MASQUE and OpenVPN over WG run, and degrade (lab bug reports).

Not proved or disproved:

* Bandwidth aggregation of one flow: ECMP is per flow; `iperf3 -P 8` uses 8
  flows. One TCP download does not get more than one lane.
* The kill switch: by kernel rule semantics it leaks (D1).
* Native "router with no container": it needs root, iproute2, nft. It
  cannot run where cfrs runs (no CAP_NET_ADMIN).

### 1.6 The podnet "router" feature, mapped to cfrs pieces

Two modes. The first one is the one the target environment needs.

**Mode A, userspace, no CAP_NET_ADMIN (per-flow L4 router).** Each new flow
(SOCKS5/HTTP CONNECT client, pod `connect`, `warp forward` connection, vnet
guest connection) ends in podnet and goes out again on one uplink that the
policy picks. There is no kernel route, no masquerade, no rp_filter: the
"hash runs twice" problem does not exist, because the flow is re-originated
on the uplink.

| mwan concept | podnet piece that exists | Change |
| --- | --- | --- |
| WAN link | `Live<WarpStack>` (src/warp/live.rs:82) for each WARP identity; a `pod_netns::Proxy` chain (crates/pod-netns/src/upstream.rs) for a SOCKS5/HTTP/tailscale uplink; direct | an `Uplink` trait: `dial(host, port)`, `udp_bind()`, `probe()`, name, weight, state |
| link creation | `WarpClient::register_or_load(path)` per state dir; `--masque-transport h2/h3`, `--leg masque/wireguard`, the egress proxy and relay as underlay (src/egress.rs, src/ws_relay.rs, src/transport/) | N identities in one process (`warp/<name>/warp.json`); per-uplink stats in place of the globals `LINK_STATS` (src/warp/ip.rs:147) and `STATS` (src/warp/proxy.rs:115) |
| ECMP weight | none | weighted choice per flow; sticky per (client, destination) for UDP |
| per-WAN table + fwmark | `warp/rules.rs` (tunnel/direct/reject per destination), pod-netns `select_chain` (upstream.rs:334: first rule wins, one hop) | a rule action `uplink:NAME` (pin by destination); pin by client = by listener or by pod session |
| failover | `race::race` (src/race.rs:54, staggered, closes the losers) used by the tunnel legs (src/tunnel.rs:291) and relay hosts (src/ws_relay.rs:464) | policy `race`: dial through 2 uplinks with a stagger, keep the first |
| TCP health check | `WarpStack::tcp_connect` (src/warp/ip.rs:635); `warp probe` targets (src/main.rs:5137-5140) | one probe task per uplink; down after K misses, up after R successes |
| link restart | `Live` watcher with `renew_due` make-before-break (live.rs:131-170), `close_session` (ip.rs:622) | a TCP-probe failure on a WARP uplink calls renew (also fixes lab bug B1) |
| kill switch | rules `reject` | no healthy uplink = refuse the flow (fail closed), configurable |
| `/status`, `/metrics` | `src/metrics.rs`, `health_log` (proxy.rs:159), `cfrs ps --json` ready doc | per-uplink state, RTT, flows |
| clients behind the router | `warp up` listeners (TCP + unix socket), `warp exec`/`cfrs pod` (`-x socks5://unix:...`), `warp forward`, `net switch` peers (src/vnet/switch.rs) | the router serves the same listeners as `warp up`, so `warp exec`, pods and vnet guests use it unchanged |

**Mode B, kernel, with CAP_NET_ADMIN (mwan done right).** `warp tun`
interfaces as WANs, plus: per-WAN tables and rules, a multipath default,
masquerade and MSS clamp, rp_filter 0, an `unreachable` default as kill
switch, all through rtnetlink (`RTM_NEWROUTE` with `RTA_MULTIPATH`,
`RTM_NEWRULE`) and nf_tables netlink, with no `ip`/`nft` binaries. The
existing route code is ioctl only (`SIOCADDRT`, src/warp/route.rs:14-16)
and cannot write tables, rules or multipath. Health probes as in mode A,
through the session (see B1 fix), not through kernel routes.

**Can it be done with no CAP_NET_ADMIN?** Yes for TCP and UDP, per flow
(mode A). The WARP side already is userspace: smoltcp in src/warp/ip.rs
(1680 lines) per session. The pod side needs no privilege either: the
seccomp backend, or the netns backend in a user namespace (its TUN is
inside the pod's own namespace). What is not possible without privilege:
ECMP of raw packets of the host, ICMP of host programs, and routing for
other hosts on the LAN. One flow on several uplinks (bonding) needs a far
end (MPTCP-like); out of scope.

---

## 2. The lab kit

### 2.1 What setup-wans.sh builds (root, `ip`, `nft`, `wg`, `openvpn`, `python3`)

1. Two `cfrs warp tun --detach` instances with fixed identities
   (`CFRS_STATE_DIR=/workspace/state/warp-a`, `warp-u`): `cfrsA` (host) and
   `cfrsU` (lines 15-21).
2. Netns `wanu`; `cfrsU` moved into it (the cfrs process stays in the host
   namespace and keeps the TUN fd), `172.16.0.2/32`, mtu 1280, default
   route `dev cfrsU` (25-30).
3. Kernel WireGuard `wgu` in `wanu` with the key of a `warp export` device
   (warp-c), peer = the public WARP key, endpoint `162.159.192.1:2408`
   (reached through cfrsU), `172.16.0.9/32`, mtu 1240 (32-38).
4. veth pairs `hwan1`/`vwan1` 10.66.0.0/30 and `hwan2`/`vwan2` 10.66.0.4/30
   (41-54).
5. In `wanu`: ip_forward, rp_filter 0, rules `from 10.66.0.0/30 lookup
   10001` (default dev wgu) and `from 10.66.0.4/30 lookup 10002` (default
   dev tun0), nft masquerade on wgu and tun0 (57-80).
6. Host: rp_filter 0 on all/default/hwan1/hwan2/cfrsA,
   `fib_multipath_hash_policy=1` (83-86).
7. OpenVPN (VPNGate) in `wanu` over wgu/cfrsU, `tun0` mtu 1200 (89-105).

Result: WAN A = `cfrsA` (MASQUE h2), WAN C = `hwan1` (kernel WG over
MASQUE), WAN D = `hwan2` (OpenVPN over WG over MASQUE). mwan example.json
matches it.

Script defects: line 90 `ip -n wanu ip link del tun0` is not a valid
command (hidden by `|| true`; tun0 is never deleted); line 32 computes
`PRIVHEX` and never uses it; line 58-60 set rp_filter on `tun0` before it
exists; the VPNGate config comes over plain `http://` (README:27). Note:
10.66.0.0/30 overlaps the vnet plan 10.66.0.0/24 (src/vnet/addr.rs).

### 2.2 The multi-WAN feature request as requirements

| Id | Requirement (FR) | podnet answer |
| --- | --- | --- |
| R1 | One named instance with several WARP devices = one aggregated WAN; NAT and MSS clamp set up automatically (FR:53-55) | `podnet router` mode A (no CAP); mode B with CAP adds masquerade + MSS clamp |
| R2 | TCP health checks before a link leaves the aggregate (FR:56-58) | per-uplink TCP probe through the session; the same probe renews a dead WARP session |
| R3 | Start/stop the TUNs from a config; persist across shells without re-registration (FR:59-61) | declarative config (src/config.rs, src/yaml.rs) + detach supervisor (src/detach.rs) + autostart (src/autostart.rs); identities already persist per state dir |
| R4 | `cfrs export --format mwan-json` (FR:62-64) | XS once the router config exists; low value if podnet routes itself |
| R5 | Weighted balancing that favors healthy lanes against 429 rate limits (FR:84-86) | weights + optional "least recent failure" bias |
| R6 | Device identities reused, no re-registration (FR:39-41) | exists (warp.json per state dir) |

### 2.3 The three bug reports against main

#### B1. MASQUE session carries ICMP/UDP but no TCP (masque-session-tcp-blackhole.md) - OPEN

* The h2 liveness check sends a PING only when no data came in, and calls
  the session dead only after 3 intervals with no pong and no data
  (src/warp/session.rs:212-296, `MAX_MISSED_PONGS` = 3 at :238). ICMP and
  UDP replies are data, so a session with dead TCP stays "alive".
* `warp tun` reconnects only when `tun::run` returns (src/main.rs:5590-5632;
  src/warp/tun.rs:286-330). No data-path probe exists.
* `--session-max-age` (the periodic renewal) is refused for `warp tun`
  (src/main.rs:4677-4683).
* The WireGuard leg checks only handshakes (src/warp/wg.rs:783-809), so the
  same "handshake yes, data no" state is not seen there either.
* The cause is on the edge side (the report shows the same host and binary
  work with another device at the same time, and a new session fixes it).
  cfrs can detect and renew; it cannot fix the edge.

Fix:
1. Userspace modes (`warp proxy`/`up`/`forward`/`run`/`nc`): a probe task
   per `Live<WarpStack>`: each 30 s when no TCP connect succeeded in that
   interval, `WarpStack::tcp_connect(1.1.1.1:443)` (configurable,
   `--probe HOST:PORT`, `off`) with a 5 s limit. After 3 misses while UDP
   DNS still answers, mark the session "tcp-dead" and renew through the
   `renew_due` path of the `Live` watcher (live.rs:131-170, make-before-break,
   old flows drain). Log `reason=tcp-probe`.
2. `warp tun`: inject a TCP SYN from the tunnel address and a reserved port
   to the probe target into `MasqueTx`; take the SYN-ACK or RST out of the
   inbound path before it reaches the TUN (match the reserved port); answer
   RST. 3 misses = `tun::run` returns an error, and the keep loop opens a new
   session. This tests the session only, not host routing or rp_filter.
3. Allow `--session-max-age` on `warp tun` (a timer around `tun::run`).
4. `cfrs status`/ready doc/`warp status`: `data_path: ok|tcp-dead`, last
   probe RTT.

Test: a unit test with a fake session that answers ICMP and UDP and drops
TCP SYN: the probe calls renew after 3 misses; a test that a SYN-ACK to the
probe port is not written to the TUN.

#### B2. Each new cfrs TUN has rp_filter 2 (warp-tun-rp-filter-strict.md) - OPEN (not caused by cfrs)

* cfrs never writes rp_filter: no match for `rp_filter` or `/proc/sys/net`
  in src/ or crates/. `Tun::create` (src/warp/tun.rs:135-232) does only
  TUNSETIFF, SIOCSIFADDR, SIOCSIFNETMASK, SIOCSIFMTU, SIOCSIFFLAGS.
* Likely source: systemd-udevd runs `systemd-sysctl --prefix=/net/ipv4/conf/IF`
  on each new interface, and systemd's 50-default.conf has
  `net.ipv4.conf.*.rp_filter = 2`. This ignores the runtime `default = 0`.
* The report calls 2 "strict"; 2 is loose (RFC 3704). Loose mode drops a
  packet whose source has no route on any interface. That fits a host whose
  only egress is a loopback proxy (no default route in main) and WAN routes
  only in per-WAN tables (rp_filter does not use the fwmark unless
  `src_valid_mark=1`). rp_filter does not depend on the protocol, so it
  does not explain "ICMP yes, TCP no" alone.
* The effective value is `max(conf.all, conf.IF)`.

Fix: after `Tun::create`, write `0` to `/proc/sys/net/ipv4/conf/IF/rp_filter`
(cfrs has CAP_NET_ADMIN in that namespace); check it again 2 s later (udev
can run after cfrs) and at each new session; warn when the effective value
is not 0 (`conf.all` = 1 overrides); `--keep-rp-filter` to opt out; show it
in the ready doc and in `cfrs doctor`. Test: on a host that permits TUN, the
value is 0 after create; a unit test of the "effective value" function.

#### B3. Exported device in kernel WireGuard: handshakes fresh, data one-way (warp-export-kernel-wg-data-path-degrades.md) - OPEN (docs + detection)

* `warp export` writes the reserved bytes only as a comment:
  `# Reserved = a,b,c (for the clients that send it)` (src/warp/export.rs:190-193;
  JSON `reserved` at :217). Kernel WireGuard sends zeros there.
* cfrs's own WireGuard leg sends the device's `client_id` bytes in bytes 1-3
  of each message (src/warp/wg.rs:6-7, :285, :344-351, :495).
* No cfrs code checks the data path of an exported device.

Fix: (1) docs and export header: what the reserved bytes are, that kernel
WireGuard and wg-quick send zeros, that `cfrs warp tun --leg wireguard` sends
them; (2) `cfrs warp export --check`: run the cfrs WireGuard leg with the
exported device, once with the reserved bytes and once with zeros, and do a
TCP probe through each: prints "device ok", "needs reserved bytes" or "device
data path dead, use --new"; (3) the same TCP probe in `WgKeepalive`
(wg.rs:783) for `--leg wireguard`. Test: unit test that `seal` with zero
reserved differs only in bytes 1-3; live test in `live.yml`.

---

## 3. Field report (cfrs 0.3.0-beta.12): work items

| Id | Item | Kind | Claim checked against main |
| --- | --- | --- | --- |
| F1 | Persistent pod sessions (`warp exec --detach`, joinable) | feature + bug | The pod ends when its first child exits: seccomp `supervise_seccomp` sets `shutdown` on `waitpid(pid)` (crates/pod-netns/src/seccomp.rs:684-695), drains relays 3 s (`RELAY_DRAIN`), exits; netns returns on `waitpid(pid)` (netns.rs:1033-1040). A program that daemonizes (`rad node start` spawns `radicle-node`) loses its network when `rad` exits. File unix sockets are not per pod (seccomp has no namespace; the netns backend only bind-mounts resolv.conf, netns.rs:1115-1130), so the control socket is missing because the node lost its supervisor, not because of isolation. `warp exec` has no `--detach` (Exec args: src/main.rs:4431-4438). |
| F2 | seccomp: TCP_NODELAY EOPNOTSUPP, peer resets | bug (confirmed in code) | On a successful TCP connect the supervisor removes the fd from its table: `map.remove(&fd)` (seccomp.rs:1056). After that: `setsockopt` is passed to the kernel AF_UNIX socket (only tracked fds are "pretended", seccomp.rs:773-780) = EOPNOTSUPP (os error 95) for TCP_NODELAY and TCP_KEEPIDLE; `getsockname`/`getpeername` are passed through (seccomp.rs:1746-1748) = the AF_UNIX address. The evidence log line 12 shows exactly `local_addr ... ss_family: 1, len: 2`, `peer_addr ... ss_family: 1`. Also: `getpeername` of a tracked stream gives the local `bound` address, not the peer (seccomp.rs:1757-1758); the fd table is keyed by fd number only and shared by all processes of the pod (seccomp.rs:698; `close` of fd N in any process drops it, :786). The only test covers a UDP socket (crates/pod-netns/tests/seccomp.rs:1458-1487); README claims the logical address for all (crates/pod-netns/README.md:127). TCP_NODELAY alone is a WARN in radicle; the AF_UNIX peer/local address (Rust `peer_addr()` gives `InvalidInput` for AF_UNIX) is the stronger candidate for the resets. Not proven without a radicle run. |
| F2b | One line at exec time for the seccomp limits; INFO log of emulation | feature | Only `pod doctor`/one warning when memory writes are refused (doctor.rs:257, seccomp.rs:888-897). `warp exec` passes `--prefer-udp` always (src/warp/up.rs:636), so `auto` takes seccomp first even where netns works (crates/pod-netns/src/lib.rs:178-180); that is why the reporter got seccomp. `warp exec` has no `--backend`. |
| F3 | `warp exec` does not find a `warp up` with another CFRS_STATE_DIR | bug | `exec_in_pod`, `shell`, `nc::via_running` and agent use `socket_path()` = `run_dir()/warp.sock` (src/warp/up.rs:30-32, :670, :715; src/warp/nc.rs:28, :213; src/agent.rs:361). `run_dir()` = CFRS_RUN_DIR, else `$XDG_RUNTIME_DIR/cfrs/run`, else `STATE/run` (src/instances.rs:38-57). `CFRS_WARP_SOCKET` is written to warp.env (up.rs:249) and to the pod program (up.rs:702) but nothing reads it. The reporter's fix was CFRS_STATE_DIR, not CFRS_WARP_SOCKET. warp.env is in the same state-dependent dir, so "read the env file" alone is circular. |
| F4a | `warp forward --resolve` | bug (flag silently ignored) + feature | `--resolve` is global (src/main.rs:80-83) and parses on `warp forward`, but forward dials with `proxy::dial` -> `resolve_all` through the tunnel (src/warp/proxy.rs:991-997, :1205-1222, :1227); pins are read only in the host chain `resolve_chain` (src/resolve.rs:236). Workaround: `-L 18776=IP:8776`. |
| F4b | Forwards in `cfrs ps` / `warp forward --list` | partly done | The ready doc has `forward: [{listen, to}]` (src/main.rs:5446-5455), so `cfrs ps --json` shows it. Text `cfrs ps` shows only the first `listen` (main.rs:1896-1901); the extra line prints `forward` only when it is a string (main.rs:1913-1919), so targets are not shown. |
| F5 | Default state dir on a shared disk | note | CFRS_STATE_DIR works (src/state.rs:6-10). No change; document. |
| F6 | `--env-file` / hint | feature | Part of F3. |
| F9a | `nohup: failed to run command 'cfrs'` | not a cfrs bug | cfrs runs itself by `current_exe()` (up.rs:48, :683; detach.rs:417); the message came from the caller's `nohup cfrs`. |

Work items:

* **W-F2 seccomp: keep TCP sockets tracked after connect** (bug, M).
  Where: crates/pod-netns/src/seccomp.rs `handle_connect`, `Sock`,
  `handle_sockname`, setsockopt branch, `close` branch. What: keep a
  `Sock::Stream { state: Connected { peer }, .. }` entry (the relay takes the
  pair; the entry keeps the metadata); `getpeername` = peer (the fake IP of a
  name), `getsockname` = a plausible local address, `setsockopt` = 0,
  `getsockopt(TCP_NODELAY)` = the value set; key the table by socket identity
  (inode from `/proc/PID/fd/N`) or by (tgid, fd) with fork handling.
  Acceptance: a C test under `--backend seccomp`: TCP connect through the
  test SOCKS proxy, then `setsockopt(TCP_NODELAY)` = 0,
  `getpeername` = AF_INET target:port, `getsockname` = AF_INET; a two-process
  test where the child closes its fd N and the parent's fd N stays tracked.
* **W-F3 socket discovery** (bug, S). Where: src/warp/up.rs `socket_path`,
  `exec_in_pod`, `shell`; src/warp/nc.rs; src/agent.rs:361. What: read
  `CFRS_WARP_SOCKET` first; `--socket PATH` on exec/shell/nc; `warp up`
  writes a pointer file at a fixed per-user place (`$XDG_RUNTIME_DIR/cfrs/`
  else `$TMPDIR/cfrs-UID/`, 0600, owner check) with the socket and state dir;
  the error lists each path tried and the running one it found. Add
  `CFRS_WARP_SOCKET` to src/manual/facts.rs. Acceptance:
  `CFRS_STATE_DIR=$A cfrs warp up`, then `env -u CFRS_STATE_DIR cfrs warp
  exec -- true` exits 0, or fails with a message that names
  `CFRS_STATE_DIR=$A`; unit test of the lookup order.
* **W-F2b backend choice and notice** (S). Where: src/warp/up.rs:633-647,
  src/main.rs Exec/Shell args, crates/pod-netns/src/lib.rs:175-192. What:
  `--backend` on `warp exec`/`warp shell`; with `--prefer-udp`, take netns
  when `probe_mem_write` fails; print one stderr line naming the backend and
  its limits (quiet with `-q`/`POD_NETNS_QUIET`). Acceptance: test that the
  line appears once and that `--backend netns` reaches the pod args.
* **W-F1 pod outlives its first child; detach and join** (feature, L; the
  seccomp part alone M). Where: seccomp.rs:684-695 and the POLLHUP exit
  path; netns.rs:1033-1045; src/warp/up.rs; src/detach.rs. What: (a) when the
  first child exits and other tasks still use the filter, return its exit code
  to the caller and keep a forked supervisor until POLLHUP (no task left);
  (b) `warp exec --detach --name N -- CMD` under the detach supervisor;
  (c) `warp exec --join N -- CMD`: seccomp = share the session's inbound dir
  (loopback listeners) and fake-DNS state; netns = `setns` into
  `/proc/PID/ns/{user,net}` of the session. Acceptance: `warp exec -- sh -c
  'daemon_that_connects_later & exit 0'`: the daemon's later TCP connect
  through the pod succeeds; `--join` reaches a 127.0.0.1 listener of the
  detached session; `cfrs ps` lists the session.
* **W-F4b forwards in ps** (XS). Where: src/main.rs:1892-1920. What: for an
  array `forward`, print each `LISTEN -> TO`; `warp forward --list` = `cfrs
  ps` filtered to forwards. Acceptance: unit test of the text rows from a
  record with two forwards.
* **W-F4a pins in tunnel DNS** (S). Where: src/resolve.rs (a public
  `pinned(name)`), src/warp/proxy.rs:1205, :1227. What: `resolve_all`/
  `resolve` return the pin before any query; `--resolve` and `CFRS_RESOLVE`
  then work for forward, proxy, nc, exec. Acceptance: unit test: a pinned
  name gives the pin and sends no DNS packet into the stack.

---

## 4. Ranked work items for the plan

| Rank | Item | Kind | Size |
| --- | --- | --- | --- |
| 1 | W-F2 seccomp: track TCP fds after connect, correct getpeername, per-socket key | bug | M |
| 2 | B1 data-path TCP probe + renew (userspace modes, `warp tun` SYN probe, `--session-max-age` on tun, status field) | bug | M |
| 3 | W-F3 `warp exec`/`shell`/`nc` socket discovery (`CFRS_WARP_SOCKET`, pointer file, `--socket`, error text) | bug | S |
| 4 | W-F2b `--backend` on exec/shell; auto avoids seccomp when memory writes fail; one-line notice | bug/feature | S |
| 5 | B2 rp_filter 0 on the TUN, re-check, warn, doctor row | bug | S |
| 6 | W-F4b forwards in `cfrs ps` text; `warp forward --list` | feature | XS |
| 7 | W-F4a `--resolve` pins in tunnel DNS | bug | S |
| 8 | W-F1 pod outlives first child; `warp exec --detach/--join` | feature | L (seccomp keep-alive alone M) |
| 9 | B3 export docs (reserved bytes) + `warp export --check` + WG-leg data probe | docs/feature | S (docs) + M |
| 10 | Router mode A: userspace multi-uplink (N WARP identities + proxy chains), weighted/sticky/race policy, TCP health, fail-closed, status | feature | L |
| 11 | Router config + `up`/`down` + autostart (R3); `--format mwan-json` (R4) | feature | M (+XS) |
| 12 | Router mode B: rtnetlink tables/rules/multipath, nft masquerade + MSS clamp, `unreachable` kill switch (with CAP_NET_ADMIN) | feature | L |
| 13 | Live multi-WAN test from the lab kit (2 identities, probes, failover) in `live.yml` | test | M |

## 5. Questions for the owner

1. Router: mode A (userspace, the target environment) only first, and mode B
   (kernel, root labs) later or never?
2. B1: may cfrs renew a session by itself on a failed TCP probe (new egress
   address, open TCP flows drain 90 s)? Default probe target `1.1.1.1:443`?
3. `warp exec` default: keep seccomp first (all UDP) or netns first (correct
   socket calls, DNS-only UDP) once W-F2 is done?
4. A per-user pointer file outside the state dir for `warp up` discovery:
   accepted?
5. R4 `mwan-json` export: keep, or drop because podnet routes itself?
6. N WARP registrations for one router: the registration rate limit (error
   1015, commit 3bed023) bounds how many uplinks a host can mint.
