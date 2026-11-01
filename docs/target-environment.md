# Target environment

cfrs is for Linux hosts with strong network limits. This document gives the
hosts that were measured, the other host conditions that cfrs must handle,
and the rules of cfrs for them.

Each fact has a date and a mark:

* **measured**: a command ran on the host, and the result is given.
* **inferred**: the fact comes from the code or from documents, not from a run.

## Measured hosts

### A sandbox with an egress proxy (2026-11-01)

The tools: `cfrs status`, `pod-netns doctor --json`, `cfrs net doctor`,
`openssl s_client -proxy`, `curl`, `cfrs demo`.

| Fact | Result | Mark |
| --- | --- | --- |
| Egress | One HTTP `CONNECT` proxy, named in `HTTPS_PROXY` | measured |
| TLS roots | `SSL_CERT_FILE` names a private bundle (123 roots) | measured |
| TLS to `api.trycloudflare.com` through the proxy | The real chain (Google Trust Services). The proxy does not re-terminate TLS for this name. | measured |
| `CONNECT` to an IP address (`1.1.1.1:443`) | The proxy resets the connection | measured |
| `CONNECT` to `cloudflare-dns.com:443` | Works (HTTP 200 from DoH) | measured |
| `CONNECT` to the edge (`198.41.200.x:7844`) | The proxy resets the connection | measured |
| QUIC on UDP 7844, no proxy | No answer (the handshake times out); `cfrs net doctor`: `UDP egress ... ? unknown` | measured |
| `listen(2)` after `bind(2)` (AF_INET, AF_UNIX) | Allowed (`SO_ACCEPTCONN=1`) | measured |
| DNS on UDP 53 to `1.1.1.1` | An answer | measured |
| `unshare(CLONE_NEWUSER)`, `unshare(CLONE_NEWNET)` | Allowed | measured |
| `bind(AF_INET6, [::1]:0)` | `EAFNOSUPPORT` | measured |
| `/dev/net/tun` | Present | measured |
| `seccomp(SECCOMP_RET_USER_NOTIF)` | A listener installs | measured |

The effect: a quick tunnel cannot reach the edge from this host. Edge
discovery works through the proxy with DNS over HTTPS by name, because the
proxy refuses DoH by IP address. The test suite of cfrs runs here.

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
| No system resolver | Names come from DoH by IP address at `1.1.1.1` | measured |
| No system resolver, `1.1.1.1` and `1.0.0.1` blocked | Names come from DoH by IP address at Google (`8.8.8.8`) | measured |
| A local `CONNECT` proxy in `HTTPS_PROXY` | DoH by IP (`1.1.1.1:443`), the API, the HTTP/2 edge leg (`:7844`) and the fetch of the public URL go through it; no QUIC is tried | measured |
| Unprivileged user namespaces | AppArmor limits them: a namespace can be made, but `lo` cannot come up | measured |
| `cfrs warp run --backend seccomp` | Works (`warp=on`) | measured |

## Other host conditions

| Condition | What cfrs does | Mark | Code or test |
| --- | --- | --- | --- |
| `HOME` is not set | The state directory is `cfrs-<uid>` in the temporary directory, never the current directory | measured (test) | `src/state.rs`; `tests/cli.rs` `an_empty_environment_works` |
| The uid has no passwd entry | cfrs reads the home from `HOME` only and does not call `getpwuid` | inferred | `src/state.rs`; only the Tailscale SSH shim (`src/vnet/tailscale_ssh.rs`) handles `getpwuid` for a client |
| The temporary directory is `noexec` | A shim goes to the first directory that is writable and not `noexec` | inferred | `src/state.rs` `exec_dir` |
| The state directory is read-only | cfrs tries the next directory of the chain; a WARP registration does not start when no directory can be written | measured (test) | `src/state.rs`; `src/warp/mod.rs` `register_or_load` |
| The proxy re-terminates TLS | Give its root with `--ca-file` or `SSL_CERT_FILE` for the API and DoH. The edge and MASQUE cannot pass through it: they need the Cloudflare chain, and MASQUE needs a client certificate | inferred | `src/trust.rs`; `tests/tls.rs` |
| The proxy refuses `CONNECT` to an IP address | DoH by name (`cloudflare-dns.com`, `dns.google`) through the proxy | measured | `src/resolve.rs` `doh_servers` |
| The proxy answers 407 | The error names each scheme of `Proxy-Authenticate`; cfrs sends Basic only | measured (test) | `tests/egress.rs` `a_407_names_the_schemes` |
| No `/proc` | The seccomp backend of `cfrs pod` cannot read the memory of the program; `pod-netns doctor` reports it | inferred | `crates/pod-netns/src/seccomp.rs` |
| The clock is wrong | A certificate error gives the clock of the host | measured (test) | `tests/tls.rs` `an_expired_certificate_names_the_host_clock` |
| `bind` is allowed and `listen` is refused | `cfrs net doctor` gives `listen(...) FAIL`; only `warp proxy`, `connect` and `net proxy` need a listener | measured (test) | `src/vnet/doctor.rs`; `tests/cli.rs` `doctor_tells_listen_from_bind` |
| Outbound UDP is refused (EPERM, ICMP) | `--protocol auto` does not try QUIC on UDP 7844 | measured (test) | `src/udp.rs`; `tunnel::plan_with_udp` |
| No IPv6 (`EAFNOSUPPORT`) | Direct dials alternate the families and go on to the next address after 250 ms | inferred | `src/egress.rs` `dial_addrs` |

## Rules of cfrs

1. Use one egress path for each connection: the proxy of `--proxy` or the
   variables, with `NO_PROXY`. Code: `src/egress.rs`. Followed by each
   command; `cfrs pod` has its own upstream list (`pod-netns -x`).
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

The doctors (`cfrs net doctor`, `cfrs pod doctor`) measure a host. Give
their output in an issue, with `cfrs status`.
