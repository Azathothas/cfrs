# cfrs

`cfrs` is one Rust binary that does the work of three tools:

| Tool | `cfrs` command |
| --- | --- |
| `cloudflared` quick tunnels and named tunnels | `cfrs tunnel`, `cfrs serve`, `cfrs share`, `cfrs connect` |
| Try Cloudflare (`*.trycloudflare.com`) | `cfrs tunnel` with no account |
| The Cloudflare WARP client | `cfrs warp` |

`cfrs` works on hosts with strong limits: no root, no TUN device, no network
namespace, no UDP, no `AF_INET` bind, or egress on TCP 443 only. The commands
`cfrs pod` and `cfrs net` give programs a network on such hosts.

The repository is a Cargo workspace:

| Crate | Contents |
| --- | --- |
| `cfrs` (root) | The CLI and the library: tunnel, service layer, WARP, virtual network. |
| `crates/cfrs-edge` | The edge client: provisioning, edge discovery, QUIC, capnp RPC, stream framing. |
| `crates/pod-netns` | A library and a CLI: run a program with all its traffic sent through a proxy. |

## Build

```sh
cargo build --release
```

The binaries are `target/release/cfrs` and `target/release/pod-netns`. Rust
1.86 or newer is necessary. The `LD_PRELOAD` shims need a C compiler at run
time (`cc`, `gcc` or `clang`). The other commands do not.

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

### Named tunnels

A named tunnel uses a Cloudflare account and a hostname from the dashboard.

```sh
cfrs tunnel --token <token> --url http://127.0.0.1:8080
cfrs tunnel --credentials-file ~/.cloudflared/<id>.json --url http://127.0.0.1:8080
```

### Edge protocol and transport

`--protocol` selects the protocol to the edge. `--transport` selects the
path.

| Leg | Socket on the host | Use it when |
| --- | --- | --- |
| `quic` | UDP 7844 | UDP to the edge is open. This is the fastest leg. |
| `http2` | TCP 7844, directly or through `HTTPS_PROXY` | UDP is blocked and TCP 7844 is open. |
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
```

* The device and its key are in `$XDG_STATE_HOME/cfrs/warp.json`
  (`~/.local/state/cfrs/warp.json`). The file mode is 0600. Use `--identity
  PATH` to use a different file, or `--ephemeral` to use a new device for one
  run.
* `cfrs warp proxy` listens on `tcp://127.0.0.1:40000` by default. Use
  `--listen unix:/path` on a host that refuses `AF_INET` binds. Names are
  resolved through the tunnel. SOCKS5 UDP ASSOCIATE is supported.
* `cfrs warp run` starts the proxy on a unix socket and runs the program with
  `cfrs pod`. The TCP connections and the DNS queries of the program go
  through WARP, also for static binaries. With the `seccomp` backend, other
  UDP datagrams also go through WARP (SOCKS5 UDP ASSOCIATE).
* The registration API calls and the MASQUE connection use `HTTPS_PROXY` when
  it is set. A proxy that terminates TLS cannot carry the MASQUE connection,
  because the connection uses a client certificate.

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

## License

0BSD. See [`LICENSE`](LICENSE). See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for the licenses of the
included third-party files.
