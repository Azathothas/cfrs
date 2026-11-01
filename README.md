# cfrs

`cfrs` is one Rust binary that does the work of three tools:

| Tool | `cfrs` command |
| --- | --- |
| `cloudflared` quick tunnels and named tunnels | `cfrs tunnel`, `cfrs serve`, `cfrs share`, `cfrs connect` |
| Try Cloudflare (`*.trycloudflare.com`) | `cfrs tunnel` with no account |
| The Cloudflare WARP client | `cfrs warp` |

`cfrs` is made for hosts with strong limits. The table gives each limit, the
part of `cfrs` for it, and where that part is tested.

| Limit on the host | Part of `cfrs` | Tested |
| --- | --- | --- |
| No UDP to the edge | HTTP/2 edge leg on TCP 7844 | CI, live against the Cloudflare edge |
| Only TCP 443 out | QUIC edge leg inside WARP (MASQUE) | CI, live |
| No DNS resolver | DNS over HTTPS by IP address (1.1.1.1, 8.8.8.8), then a static edge list | CI and a sandbox with an HTTP proxy |
| Egress through a proxy only | HTTP `CONNECT`, SOCKS5 and `NO_PROXY` for each connection | `tests/egress.rs` |
| No root, no TUN, no network namespace | `cfrs pod` (seccomp backend), `cfrs warp run` | CI and a sandbox |
| No `AF_INET` bind | `cfrs net` (shim and userspace stack), unix-socket origins | CI and a sandbox |

The live CI job (`.github/workflows/ci.yml`, job `live`) runs `cfrs demo` with
each edge leg on a GitHub runner and fetches the public URL. One limit stays:
a proxy that terminates TLS cannot carry the edge connection or the MASQUE
connection, because both need the Cloudflare certificate chain (and MASQUE
needs a client certificate).

The repository is a Cargo workspace:

| Crate | Contents |
| --- | --- |
| `cfrs` (root) | The CLI and the library: the edge client (provisioning, discovery, QUIC, HTTP/2, Cap'n Proto and its RPC), the service layer, WARP, the virtual network. |
| `crates/pod-netns` | A library and a CLI: run a program with all its traffic sent through a proxy. |

## Update

```sh
cfrs update --check              # say whether a newer release exists
cfrs update                      # install it
cfrs update --version v0.3.0-beta.1
```

`cfrs update` installs a release only after these checks: the certificate
of `SHA256SUMS.sigstore.json` chains to the Fulcio roots of Sigstore and
names `release.yml` of this repository at the tag, the signature over
`SHA256SUMS` is valid, the SHA-256 of the binary is its line in
`SHA256SUMS`, and the new binary runs and prints the version of the tag. cfrs
does not check the inclusion proof of the Rekor log. A prerelease is
installed only with `--version`, or when the current binary is a
prerelease.

## Build

```sh
cargo build --release
```

The binaries are `target/release/cfrs` and `target/release/pod-netns`. Rust
1.89 or newer is necessary.

A static binary has no run-time dependency on the C library of the host:

```sh
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=clang cargo build --release --target x86_64-unknown-linux-musl
```

The `LD_PRELOAD` shims need a C compiler at run time (`cc`, `gcc` or
`clang`). The other commands do not.

## Release binaries

Each [release](https://github.com/Azathothas/cfrs/releases) has static
Linux binaries of `cfrs` and `pod-netns` for `x86_64`, `aarch64`, `armv7`,
`riscv64gc`, `i686`, `arm` (ARMv6, hard float), `loongarch64` and
`powerpc64le`. cfrs is for Linux only. Each release also has these files:

| File | Contents |
| --- | --- |
| `SHA256SUMS` | The SHA-256 of each binary and of `cfrs.1`. |
| `SHA256SUMS.sigstore.json` | The keyless cosign signature of `SHA256SUMS`. |
| `provenance.sigstore.json` | The SLSA provenance of the binaries. |
| `cfrs.1` | The manual page (`cfrs man --roff`). |
| `THIRD-PARTY-LICENSES.md` | The license texts of the crates in the binaries. |

Verify the files before you use them. Download the binary, `SHA256SUMS` and
the two bundles to one directory. Then do these steps:

1. Check the checksums. The command ignores the files that you did not
   download:

   ```sh
   sha256sum -c --ignore-missing SHA256SUMS
   ```

2. Check the signature of `SHA256SUMS`. Replace `vX.Y.Z` with the tag:

   ```sh
   cosign verify-blob --bundle SHA256SUMS.sigstore.json \
     --certificate-identity https://github.com/Azathothas/cfrs/.github/workflows/release.yml@refs/tags/vX.Y.Z \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
   ```

3. Check the provenance of the binary. With no network access to the GitHub
   API, add `--bundle provenance.sigstore.json`:

   ```sh
   gh attestation verify cfrs-x86_64-unknown-linux-musl --repo Azathothas/cfrs \
     --signer-workflow Azathothas/cfrs/.github/workflows/release.yml
   ```

A binary that has one changed byte fails each check. The workflow
`.github/workflows/release-proofs.yml` does these checks on a fresh runner
after each release. It also does each check on a changed copy, which must
fail.

## Quick start

```sh
# Make a quick tunnel to a local HTTP server.
cfrs tunnel --url http://127.0.0.1:8080

# Make a quick tunnel to an HTTP server on a unix socket.
cfrs tunnel --unix /run/app.sock

# Test the full path: a built-in origin, a tunnel, a fetch of the public URL.
cfrs demo --exit-on-verify
```

## Tunnels

### Origins

```sh
cfrs tunnel --url http://127.0.0.1:8080   # HTTP or HTTPS origin
cfrs tunnel --port 8080                   # the same as http://127.0.0.1:8080
cfrs tunnel --unix /run/app.sock          # HTTP origin on a unix socket
cfrs tunnel --tcp 10.0.0.5:5432           # raw TCP origin
cfrs tunnel --hello-world                 # built-in test origin
cfrs tunnel --config ./config.yml         # cloudflared ingress rules
```

The service strings are the same as in cloudflared:

```text
http://host:port     https://host:port     unix:/path/to.sock
unix+tls:/path.sock  tcp://host:port       http_status:404
hello_world          metrics               static:/srv/www
spa:/srv/www
```

* `static:` serves a directory.
* `spa:` serves a directory and sends `index.html` for unknown paths.
* `metrics` serves the Prometheus metrics of the tunnel.
* `--http-host-header NAME` sets the `Host` header for the origin.
* `--no-tls-verify` does not verify the TLS certificate of an HTTPS origin.

All built-in origins run in the process. They do not open a TCP listener.

### Configuration file

`cfrs tunnel --config` reads a cloudflared YAML file:

```yaml
tunnel: <named-tunnel-token>          # optional; without it, a quick tunnel
credentials-file: /etc/cfrs/creds.json
ha-connections: 2
protocol: auto
ingress:
  - hostname: app.example.com
    path: /api
    service: http://127.0.0.1:8080
    originRequest:
      noTLSVerify: true
      connectTimeout: 5s
  - service: http_status:404
```

The last rule must match all requests.

cfrs reads the YAML with its own reader (`src/yaml.rs`). The reader accepts
block mappings, block sequences, plain and quoted scalars on one line, and
comments. It refuses anchors, aliases, tags, block scalars (`|`, `>`), flow
collections that are not empty, tabs in the indentation and duplicate keys,
and gives the line number. cfrs ignores keys that it does not use.

### Named tunnels

A named tunnel uses a Cloudflare account and a hostname from the dashboard.

```sh
TUNNEL_TOKEN=<token> cfrs tunnel --url http://127.0.0.1:8080
cfrs tunnel --credentials-file ~/.cloudflared/<id>.json --url http://127.0.0.1:8080
```

`--token <token>` also works. Other users of the host can read a command
line, so `TUNNEL_TOKEN` is safer.

### Edge protocol and transport

`--protocol` selects the protocol to the edge. `--transport` selects the
path.

| Leg | Socket on the host | Use it when |
| --- | --- | --- |
| `quic` | UDP 7844 | UDP to the edge is open. This is the fastest leg. |
| `http2` | TCP 7844, directly or through the proxy | UDP is blocked and TCP 7844 is open. |
| `quic+warp` | TCP 443 only (MASQUE) | Only TCP 443 is open. |

With the default values (`--protocol auto --transport auto`), `cfrs` tries the
legs in the order of the table. Each attempt has a time limit of 8 seconds when
another leg can follow. Other values:

| `--protocol` | `--transport` | Legs |
| --- | --- | --- |
| `auto` | `auto` | `quic`, `http2`, `quic+warp` |
| `quic` | `auto` | `quic`, `quic+warp` |
| `http2` | `auto` or `direct` | `http2` |
| `auto` | `direct` | `quic`, `http2` |
| `quic` | `direct` | `quic` |
| `auto` or `quic` | `warp` | `quic+warp` |

`--warp-identity PATH` keeps the WARP device in a file. Without it, each run
registers a new anonymous device. `CFRS_EDGE=ip:port,...` replaces edge
discovery.

### Serve a directory

```sh
cfrs serve --dir ./public
cfrs serve --dir ./app --spa          # send index.html for unknown paths
```

### Share files

```sh
cfrs share --mode upload --password                 # receive files, with a PIN
cfrs share --mode download --file ./report.pdf      # send one file
cfrs share --mode proxy --port 3000                 # share a local port, with a PIN
cfrs share --mode upload --dir /tmp/inbox --stop-after --idle-secs 600
```

* The public path is `/s/<token>/`. The token has 32 random bytes.
* `--password` adds a 6-digit PIN. The host shows the PIN. The PIN check uses
  a constant-time compare and a rate limit.
* The upload limits are 512 MiB for each file and 32 files.
* `--stop-after` stops the session after the first transfer. `--idle-secs`
  stops it after a time with no activity.

### Raw streams through a quick tunnel

A quick tunnel carries HTTP and WebSocket. `--forward` puts a WebSocket
endpoint at `/__cfrs/ws`. `cfrs connect` changes local sockets into
connections through that endpoint. Thus SSH, databases and unix sockets can
go through a quick tunnel.

```sh
# Server: expose a unix socket (or tcp://host:port).
cfrs tunnel --forward unix:/run/app.sock

# Client: local port 8080 goes to that unix socket.
cfrs connect wss://<random>.trycloudflare.com/__cfrs/ws -L tcp://127.0.0.1:8080
```

`-L` accepts `tcp://[bind:]port` and `unix:///path` and is repeatable. Each
local connection gets its own WebSocket. `--forward` and an origin can be used
together: the origin gets all paths other than `/__cfrs/ws`.

### Other commands

```sh
cfrs ports            # list the listening TCP ports (Linux)
cfrs qr <URL>         # print a QR code
```

## WARP

`cfrs warp` is a WARP client. It uses MASQUE (`CONNECT-IP` over HTTP/2) on
TCP 443. It needs no root and no TUN device.

```sh
cfrs warp register                # register a device, or load the saved one
cfrs warp status                  # the device and the account
cfrs warp status --json           # the account record as JSON
cfrs warp license <KEY>           # attach a WARP+ license key
cfrs warp rotate                  # make and enrol a new MASQUE key
cfrs warp delete                  # remove the device and the saved file
cfrs warp probe                   # test TCP connects through the tunnel
cfrs warp proxy                   # local SOCKS5 and HTTP CONNECT proxy
cfrs warp run -- curl https://cloudflare.com/cdn-cgi/trace
cfrs warp tun --name cfrs0        # TUN interface (needs CAP_NET_ADMIN)
```

* The device and its key are in `warp.json` in the state directory: the
  first that cfrs can write of `CFRS_STATE_DIR`, `$XDG_STATE_HOME/cfrs`,
  `~/.local/state/cfrs`, `$XDG_RUNTIME_DIR/cfrs` and `cfrs-<uid>` in the
  temporary directory. The file mode is 0600. cfrs checks the directory
  before it registers a device. Use `--identity PATH` for a different file,
  `--ephemeral` or `CFRS_STATE_DIR=none` to use a new device for one run.
* `cfrs warp proxy` listens on `tcp://127.0.0.1:40000` by default. Use
  `--listen unix:/path` on a host that refuses `AF_INET` binds. Names are
  resolved through the tunnel. SOCKS5 UDP ASSOCIATE is supported.
* `cfrs warp run` starts the proxy on a unix socket and runs the program with
  `cfrs pod`. The TCP connections and the DNS queries of the program go
  through WARP, also for static binaries. With the `seccomp` backend, other
  UDP datagrams also go through WARP (SOCKS5 UDP ASSOCIATE).
* `cfrs warp tun` makes a TUN interface with the tunnel address and moves its
  packets through WARP. It does not change the routes: add routes for the
  destinations to send through WARP, and keep a route for the MASQUE endpoint
  outside the interface. The command prints examples.
* The registration API calls and the MASQUE connection use the proxy (see
  "Proxies and DNS"). A proxy that terminates TLS cannot carry the MASQUE
  connection, because the connection uses a client certificate.

## Run any program through a proxy: `cfrs pod`

`cfrs pod` (the same as the `pod-netns` binary) runs a program with all its
network traffic sent through a SOCKS5, HTTP or tailnet upstream. It does not
use `LD_PRELOAD`, so static binaries and Go binaries are also covered.

```sh
cfrs pod -x socks5://127.0.0.1:1080 -- curl https://example.com
cfrs pod -x http://proxy:3128 -- git clone https://example.com/repo
cfrs pod -x socks5://unix:/run/proxy.sock -- ./static-binary
cfrs pod -- curl https://example.com        # upstream from $ALL_PROXY or $HTTPS_PROXY
cfrs pod doctor                             # which backend can run here
```

Two backends are available. `--backend auto` (the default) selects one.

| Backend | Needs | Mechanism |
| --- | --- | --- |
| `netns` | unprivileged user namespaces and `/dev/net/tun` | The program gets a network namespace. A TUN device is its only interface. A userspace TCP/IP stack sends each flow to the upstream. |
| `seccomp` | seccomp with `SECCOMP_RET_USER_NOTIF` | A seccomp filter stops the socket system calls. The supervisor answers them and gives the program connected descriptors. |

Both backends answer DNS from a fake-IP pool (`198.18.0.0/15`) and send the
name to the upstream. Thus no DNS query leaves the host. See
[`crates/pod-netns/README.md`](crates/pod-netns/README.md) for all options.

## Virtual network: `cfrs net`

`cfrs net` gives programs IP addresses on a host that refuses `AF_INET` binds.
It needs no namespace, no TUN device and no capability.

```sh
cfrs net doctor                         # what this host permits
cfrs net shim --out /tmp/cfrsnet        # build the LD_PRELOAD shim
LD_PRELOAD=/tmp/cfrsnet/libcfrsnet.so ./server      # bind 10.66.0.2:8080 works
cfrs net proxy --forward 10.66.0.2:8080=unix:/run/app.sock
cfrs net switch --listen unix:/tmp/cfrsnet.switch   # connect stacks
cfrs net proxy --switch unix:/tmp/cfrsnet.switch --address 10.66.0.3
```

See [`docs/virtual-network.md`](docs/virtual-network.md).

## Tailscale on a sealed host

```sh
cfrs net tailscale --socket /run/tailscale/tailscaled.sock   # SOCKS5 front door to the tailnet
eval "$(cfrs net socksify --proxy /tmp/cfrssocks.sock)"      # shim for tailnet connects
cfrs net ts-shims --out /run/cfrs-ts-shims                   # user tables for Tailscale SSH
cfrs pod -x tailscale:/run/tailscale/tailscaled.sock -- ssh host
```

`tailscaled` must run with `--tun=userspace-networking`.

## Proxies and DNS

Each connection of cfrs (the quick-tunnel API, DNS over HTTPS, the HTTP/2
edge leg, the WARP API, MASQUE, the fetch of the public URL) takes the same
proxy:

```sh
cfrs --proxy socks5h://127.0.0.1:1080 tunnel --url http://127.0.0.1:8080
HTTPS_PROXY=http://user:password@proxy:3128 cfrs demo --exit-on-verify
NO_PROXY=127.0.0.1,.internal cfrs warp register
cfrs --no-proxy tunnel --url http://127.0.0.1:8080
```

* `http://` uses `CONNECT`. `socks5://` resolves the name on this host;
  `socks5h://` gives the name to the proxy. cfrs refuses `socks4://` and
  `https://`.
* Without `--proxy` and `--no-proxy`, cfrs reads `HTTPS_PROXY`,
  `https_proxy`, `ALL_PROXY` and `all_proxy`. `NO_PROXY` names the targets
  that do not use the proxy.
* With a proxy, `--protocol auto` does not try QUIC on UDP 7844 (no proxy
  carries UDP), and cfrs prints one line that says so.
* A proxy that answers 407 gets a message with the schemes that it asks
  for. cfrs sends Basic only.

A direct connection resolves the name with this chain: a pin of
`--resolve HOST=IP` or `CFRS_RESOLVE`, the system resolver, then DNS over
HTTPS by IP address at Cloudflare (1.1.1.1, 1.0.0.1) and Google (8.8.8.8,
8.8.4.4). It tries each address of the name, and starts the next attempt
250 ms after the one before.

## TLS roots

cfrs checks the certificate of each TLS server that it connects to. Behind a
proxy that inspects TLS, give the root of the proxy:

```sh
SSL_CERT_FILE=/etc/corp-root.pem cfrs tunnel --url http://127.0.0.1:8080
cfrs --ca-file /etc/corp-root.pem warp register
```

`--ca-file` and `SSL_CERT_FILE` replace the other roots. Without them, cfrs
trusts `cfrs-ca.pem` beside the binary, the first system bundle that it can
read (for example `/etc/ssl/certs/ca-certificates.crt`), and the Mozilla
roots compiled into cfrs. `cfrs status` shows the roots in `tls_roots`. See
`SECURITY.md`.

## Manual, status and exit codes

`cfrs man` shows the manual. It is generated from the command tree of the
binary, so it always agrees with `--help`. It needs no man(1), no groff and no
network.

```sh
cfrs man                      # the whole manual, in a pager on a terminal
cfrs man warp run             # one command
cfrs man exit-status          # one topic: environment, files, exit-status, examples, pod
cfrs man --roff > cfrs.1      # a man(7) page (also a release asset)
cfrs man --json               # the tables, for a program
cfrs status                   # one JSON line about this host; no network
cfrs ports --json             # the listening TCP ports, as one JSON object
```

With `--json`, `cfrs tunnel`, `serve`, `share` and `demo` write JSON lines on
stdout in place of the text lines. A line with `"event": "ready"` gives
`url`, `tunnel_id` and `locations` (and `pin` for `share`). A line with
`"event": "verified"` comes after the fetch of the public URL.

The exit codes follow sysexits.h: 64 for a bad command line, 69 when a
service or a network path is not available (no edge leg worked), 78 for a
bad configuration (for example `CFRS_EDGE`). `cfrs man exit-status` gives all
of them.

`CFRS_ERROR_PROGRAM=/path/to/program` gives a JSON report of each failure
(version, system, command, exit code, the last 64 log lines) to that program
on its stdin. Credentials are masked. Use it to collect failures in tests.

## Library

```rust
use cfrs::{Service, Tunnel};

# async fn run() -> anyhow::Result<()> {
let handle = Tunnel::quick()
    .service(Service::parse("http://127.0.0.1:8080")?)
    .ha_connections(2)
    .build()?
    .start()
    .await?;
println!("{:?}", handle.url());
handle.verify(None).await?;
handle.shutdown().await;
# Ok(())
# }
```

* `cfrs::Ingress` holds ordered rules for a tunnel with more than one service.
* `cfrs::warp::WarpClient` registers a device and opens a `WarpStack`, which
  has `tcp_connect` and `udp_bind` through the tunnel.
* `cfrs::vnet::NetStack` is the userspace IP stack.
* `pod_netns::main_with_args` runs the `pod-netns` command line. The modules
  `pod_netns::upstream`, `socks`, `dns` and `tailscale` are also public.

## Documents

* [`docs/protocol.md`](docs/protocol.md): the edge protocol and the WARP protocol.
* [`docs/virtual-network.md`](docs/virtual-network.md): the shim, the stack and switch mode.
* [`crates/pod-netns/README.md`](crates/pod-netns/README.md): pod-netns.
* [`SECURITY.md`](SECURITY.md): how to report a vulnerability, what
  Cloudflare can see, what listens, where secrets are kept.

## License

0BSD. See [`LICENSE`](LICENSE). See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for the licenses of the
included third-party files.
