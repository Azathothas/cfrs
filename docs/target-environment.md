# Target environment

podnet is for Linux hosts with strong network limits. This document gives the
hosts that were measured, the other host conditions that podnet must handle,
and the rules of podnet for them.

Each fact has a date and a mark:

* **measured**: a command ran on the host, and the result is given.
* **inferred**: the fact comes from the code or from documents, not from a run.

## Measured hosts

### A sandbox with an egress proxy (2026-11-01)

The tools: `podnet status`, `podnet doctor`, `podnet pod doctor --json`, `podnet net doctor`,
`openssl s_client -proxy`, `curl`, `podnet demo`.

| Fact | Result | Mark |
| --- | --- | --- |
| Egress | One HTTP `CONNECT` proxy, named in `HTTPS_PROXY` | measured |
| TLS roots | `SSL_CERT_FILE` names a private bundle (123 roots) | measured |
| TLS to `api.trycloudflare.com` through the proxy | The real chain (Google Trust Services). The proxy does not re-terminate TLS for this name. | measured |
| `CONNECT` to an IP address (`1.1.1.1:443`) | The proxy resets the connection | measured |
| `CONNECT` to `cloudflare-dns.com:443` | Works (HTTP 200 from DoH) | measured |
| `CONNECT` to the edge (`198.41.200.x:7844`) | The proxy resets the connection | measured |
| `podnet doctor` (2026-11-01): `CONNECT` to the edge on 7844 (name and address) and to MASQUE `162.159.198.2:443` | The proxy answers 200, then no TLS byte comes back: "the proxy answers and carries nothing". `api.trycloudflare.com` (Google Trust Services) and `api.cloudflareclient.com` (Let's Encrypt) have valid chains. 0 of 3 legs can work. | measured |
| QUIC on UDP 7844, no proxy | No answer (the handshake times out); `podnet net doctor`: `UDP egress ... ? unknown` | measured |
| `listen(2)` after `bind(2)` (AF_INET, AF_UNIX) | Allowed (`SO_ACCEPTCONN=1`) | measured |
| DNS on UDP 53 to `1.1.1.1` | An answer | measured |
| `unshare(CLONE_NEWUSER)`, `unshare(CLONE_NEWNET)` | Allowed | measured |
| `bind(AF_INET6, [::1]:0)` | `EAFNOSUPPORT` | measured |
| `/dev/net/tun` | Present | measured |
| `seccomp(SECCOMP_RET_USER_NOTIF)` | A listener installs | measured |

The effect: a quick tunnel cannot reach the edge from this host. Edge
discovery works through the proxy with DNS over HTTPS by name, because the
proxy refuses DoH by IP address. The test suite of podnet runs here.

### A GitHub runner, ubuntu-24.04 (2026-10-31 and 2026-11-01)

The tools: `.github/workflows/live.yml` (run 41260604779), `release.yml`
(`release-short.sh`).

| Fact | Result | Mark |
| --- | --- | --- |
| QUIC on UDP 7844 | Registers | measured |
| HTTP/2 on TCP 7844 | Registers | measured |
| QUIC inside WARP MASQUE on TCP 443 | Registers | measured |
| UDP 7844 dropped (`iptables DROP`) | `--protocol auto` registers over HTTP/2 after 2.4 s (the 2 s stagger) | measured |
| UDP and TCP 7844 dropped | `--protocol auto` registers over `quic+warp` after 6.7 s (two 2 s staggers and the WARP setup) | measured |
| UDP and TCP 7844 dropped, `--transport relay` | `http2+relay` registers through `tcp.ssh.relay.ajam.dev` in 0.74 s (ord02); the public URL answers 200 (run 41303368779) | measured |
| No system resolver | Names come from DoH by IP address at `1.1.1.1` | measured |
| No system resolver, `1.1.1.1` and `1.0.0.1` blocked | Names come from DoH by IP address at Google (`8.8.8.8`) | measured |
| A local `CONNECT` proxy in `HTTPS_PROXY` | DoH by IP (`1.1.1.1:443`), the API, the HTTP/2 edge leg (`:7844`) and the fetch of the public URL go through it; no QUIC is tried | measured |
| Unprivileged user namespaces | AppArmor limits them: a namespace can be made, but `lo` cannot come up | measured |
| `podnet warp run --backend seccomp` | Works (`warp=on`) | measured |

### An IPv6-only host (the IPv6-only kit, 2026-11-02; a runner, from beta.7)

The kit of 2026-11-02 ran podnet 0.3.0-beta.6 in a netns and in a VM with
IPv6 only (NAT66 out through WARP). `scripts/v6only/` makes the same host
on a runner: the namespace `v6up` has IPv4 and `podnet warp tun
--default-route`; `v6only` behind it has IPv6 only (no IPv4 route; the
address 127.0.0.1 stays). The step "An IPv6-only host" of `live.yml` runs
`scripts/v6only/acceptance.sh`.

| Fact | Result | Mark |
| --- | --- | --- |
| A connect to an IPv4 address | `ENETUNREACH` | measured (kit) |
| `podnet warp run` (beta.6) | IPv4 and UDP for the program through WARP; a tunnel at 1.9 to 2.2 MB/s | measured (kit) |
| A tunnel with TCP 443 and DNS only (beta.6) | Ready in 13 s; after `kill -9`, the supervisor starts it again in less than 30 s, with a new URL | measured (kit) |
| `warp up --tun` (beta.6) | Fails: it does not give `--masque-endpoint` to `warp tun` (fixed in beta.8) | measured (kit) |
| No system resolver (beta.6) | No tunnel: the DoH servers were IPv4 only (fixed in beta.8: IPv6 servers first on a host with no IPv4 route) | measured (kit) |
| `podnet doctor` (beta.6) | "0 of 3 legs" while the tunnel works: it probed the IPv4 front door only (fixed in beta.8) | measured (kit) |

### The test box (a GitHub runner, from 2026-11-01)

`scripts/test_in_box.sh` copies the sandbox above onto a runner, with no
Podman box: `iptables -m owner` lets the user `podnetbox` reach only
`scripts/box/proxy.py` (names on 443, the MASQUE address, the refusal
texts of the sandbox) and a fault stand-in. No UDP, no direct TCP, no
DNS, no IPv6. `scripts/box/probe.py` checks the box against
`scripts/box/report.txt` first, and a proxy that allows each target must
fail that check. The steps:

| Step | Expected |
| --- | --- |
| `podnet --version` | runs (a binary that exits 3 makes the box exit 1) |
| probe, then a planted wrong policy | the box matches; the planted policy fails |
| `podnet doctor` | `quic` and `http2` refused, `quic+warp` ok |
| `demo --transport direct` (negative control) | fails |
| `demo` | registers on `quic+warp` through the proxy, and the URL answers |
| `demo` with the MASQUE address refused (negative control) | fails |
| an edge that accepts and says nothing | the HTTP/2 leg fails in its limit, no hang |

`.github/workflows/live.yml` runs it on each push and each day.

## Other host conditions

| Condition | What podnet does | Mark | Code or test |
| --- | --- | --- | --- |
| `HOME` is not set | The state directory is `podnet-<uid>` in the temporary directory, never the current directory | measured (test) | `src/state.rs`; `tests/cli.rs` `an_empty_environment_works` |
| The uid has no passwd entry | podnet reads the home from `HOME` only and does not call `getpwuid` | inferred | `src/state.rs`; only the Tailscale SSH shim (`src/vnet/tailscale_ssh.rs`) handles `getpwuid` for a client |
| The temporary directory is `noexec` | A shim goes to the first directory that is writable and not `noexec` | inferred | `src/state.rs` `exec_dir` |
| A shim directory in `/tmp` exists already (another user made it) | podnet uses the directory only when it belongs to this user, is not a symlink, and other users cannot write it; else it tries the next directory. A cached library is used only when it is a file of this user that other users cannot write | measured (test) | `src/state.rs` `exec_dir_refuses_a_directory_open_to_others`; `src/vnet/shim.rs` `a_planted_library_is_not_used_from_the_cache` |
| The state directory is read-only | podnet tries the next directory of the chain; a WARP registration does not start when no directory can be written | measured (test) | `src/state.rs`; `src/warp/mod.rs` `register_or_load` |
| The proxy re-terminates TLS | Give its root with `--ca-file` or `SSL_CERT_FILE` for the API and DoH. The edge and MASQUE cannot pass through it: they need the Cloudflare chain, and MASQUE needs a client certificate | inferred | `src/trust.rs`; `tests/tls.rs` |
| The proxy refuses `CONNECT` to an IP address | DoH by name (`cloudflare-dns.com`, `dns.google`, `dns.google.com`) through the proxy | measured | `src/resolve.rs` `settings` (`pod_dns::Names::Last`) |
| The proxy answers 407 | The error names each scheme of `Proxy-Authenticate`; podnet answers Basic and Digest (MD5, MD5-sess, SHA-256, SHA-256-sess), and the advice follows what it sent | measured (test) | `PodUtils/podcrates:crates/pod-proxy/src/proxy_auth.rs` `a_407_names_the_schemes`, `a_407_with_digest_does_not_say_basic_only`; `tests/egress.rs` `a_407_names_the_schemes` |
| No `/proc` | The seccomp backend of `podnet pod` cannot read the memory of the program; `podnet pod doctor` reports it | inferred | `crates/podnet-netns/src/seccomp.rs` |
| `/proc/<pid>/mem` and `process_vm_writev` are refused | `getsockname` and `getpeername` answer `EOPNOTSUPP` under the seccomp backend; QUIC clients fail, and a program that reads its own address can crash (a Go `LocalAddr()` type assertion). A warning and the `write program memory` row of `pod doctor` say so; `--backend netns` avoids it | measured (issue 186) | `crates/podnet-netns/src/sockopt.rs` `handle_sockname`; `tests/pod_seccomp.rs` `getpeername_is_the_inet_address_or_eopnotsupp` |
| The clock is wrong | A certificate error gives the clock of the host | measured (test) | `tests/tls.rs` `an_expired_certificate_names_the_host_clock` |
| `bind` is allowed and `listen` is refused | `podnet net doctor` gives `listen(...) FAIL`; only `warp proxy`, `connect` and `net proxy` need a listener | measured (test) | `src/vnet/doctor.rs`; `tests/cli.rs` `doctor_tells_listen_from_bind` |
| Outbound UDP is refused (EPERM, ICMP) | `--protocol auto` does not try QUIC on UDP 7844 | measured (test) | `src/udp.rs`; `tunnel::plan_with_udp` |
| No IPv6 (`EAFNOSUPPORT`) | Direct dials alternate the families and go on to the next address after 250 ms | inferred | `PodUtils/podcrates:crates/pod-proxy/src/race.rs` `dial_addrs` |

## Other networks to the front door

podnet has no built-in Tor or Psiphon client. Each of these networks gives a
local SOCKS5 or HTTP proxy, and `--proxy` sends the connections of podnet
(the WARP API and the MASQUE session) through it. The WARP traffic then
leaves the other network at its exit, and the front door sees that exit.

* Tor (issue 159). Start `tor`; it listens on SOCKS5 127.0.0.1:9050.

  ```sh
  podnet --proxy socks5h://127.0.0.1:9050 warp register
  podnet --proxy socks5h://127.0.0.1:9050 warp proxy
  ```

  The API can refuse a Tor exit. Then register with no proxy, and use
  `--proxy` for the session only (`warp proxy` loads the saved device).
  `--no-relay` keeps the session on Tor: the WebSocket relay is a second
  path that does not use Tor.
* Psiphon (issue 158). The console client of psiphon-tunnel-core gives a
  SOCKS5 port and an HTTP port (`LocalSocksProxyPort` and
  `LocalHttpProxyPort` of its config).

  ```sh
  podnet --proxy socks5h://127.0.0.1:PORT warp --no-relay proxy
  ```

* A command as the carrier: `--proxy 'http+exec:COMMAND'` runs COMMAND for
  each connection and speaks HTTP `CONNECT` on its stdin and stdout, as the
  `ProxyCommand` of SSH.
* A nested session (issue 156): a second device whose session goes through
  the first. The front door of the second device sees the exit of the
  first.

  ```sh
  podnet warp --identity a.json proxy --listen tcp://127.0.0.1:40000 &
  podnet --proxy socks5h://127.0.0.1:40000 warp --identity b.json proxy \
      --listen tcp://127.0.0.1:40001
  ```

  The clients of 40001 use the second device. Each packet is in two
  sessions, so the MTU and the speed are lower.

`scripts/live-batch2.sh` (in `.github/workflows/live.yml`) checks the nested
session.

## Rules of podnet

1. Use one egress path for each connection: the proxy of `--proxy` or the
   variables, with `NO_PROXY`. Code: `src/egress.rs`, over `pod-proxy`. Followed by each
   command; `podnet pod` has its own upstream list (`podnet pod -x`).
2. Do not send UDP around a proxy. Code: `tunnel::plan_with_proxy`.
3. Resolve names with a chain that works with no system resolver. Code:
   `src/resolve.rs`.
4. Check each TLS certificate; take extra roots only from the user. Code:
   `src/trust.rs`.
5. Write no file in the current directory unless the user names it; keep
   secrets in private files. Code: `src/state.rs`, `src/warp/mod.rs`.
6. Say which hop failed. Code: `src/hop.rs`.
7. Start the next edge leg after a short stagger, not after a full time
   limit. Code: `src/race.rs`.

The doctors (`podnet doctor`, `podnet net doctor`, `podnet pod doctor`) measure a host. Give
their output in an issue, with `podnet status`.
