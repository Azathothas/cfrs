# The Cloudflare quick-tunnel protocol, and what works in a sealed sandbox

This is the deep dive behind `cfrs`. The reference implementation is
`cloudflare/cloudflared`, studied at commit
`bf4f5020be590fb9924c8982ac479a32f05de269` (2026-10-08). File references below
are to that tree; the behaviour is mirrored by the `cloudflare-quick-tunnel`
crate that `cfrs` uses.

## 1. Control plane, provisioning

`cloudflared tunnel --url ...` with no account runs `RunQuickTunnel`
(`cmd/cloudflared/tunnel/quick_tunnel.go`). It issues exactly one request:

```
POST https://api.trycloudflare.com/tunnel
Content-Type: application/json
User-Agent: cloudflared/<version>
```

The body is empty for a public quick tunnel. For a **protected** (email
allow-list) quick tunnel the body is `{"auth_mode":"otp"}` and the CLI is given
`--allowed-mail` (`buildQuickTunnelRequestBody`). A successful response is:

```json
{"success":true,"result":{
  "id":"<uuid>","name":"qt-...","hostname":"<random>.trycloudflare.com",
  "account_tag":"<hex>","secret":"<base64 32 bytes>"},"errors":[]}
```

`id`, `account_tag` and `secret` are the `TunnelAuth` credentials the edge wants
on registration. The endpoint is overridable with `--quick-service`; the
default is hard-coded at `cmd/cloudflared/tunnel/cmd.go:872`. The provisioning
call is plain HTTPS on 443, this is the only part that is trivially reachable
from a normal network.

### The email allow-list

The newer protected mode (`quicktunnelauth/`) does not put the mailbox list in
the provisioning request. `--allowed-mail` builds a local
`QuickTunnelAuthRecipientPolicy`; the local cloudflared then runs an OTP gate in
front of the tunnel: an unauthenticated browser is redirected to
`https://login.trycloudflare.com`, which returns a signed ES256 JWT
(`quick_tunnel_auth` assertion) bound to the quick-tunnel hostname and a
one-time state. The validator checks issuer `https://login.trycloudflare.com`,
audience `cloudflared-quick-tunnel`, a 2-minute TTL, the callback hostname and
the recipient policy (`quicktunnelauth/assertion.go`, `handler.go`). In other
words the allow-list is enforced at the **origin-side cloudflared**, not by the
edge, and it is unavailable to a client that only speaks the tunnel protocol.

## 2. Data plane, the edge connection

Edge addresses come from the SRV record
`_v2-origintunneld._tcp.argotunnel.com`, which yields
`region1.v2.argotunnel.com` / `region2.v2.argotunnel.com` on port **7844**
(`edgediscovery/allregions`). Two transports are supported
(`connection/protocol.go`):

| protocol | socket | TLS SNI | ALPN |
| --- | --- | --- | --- |
| `quic` | UDP 7844 | `quic.cftunnel.com` | `argotunnel` |
| `http2` | TCP 7844 | `h2.cftunnel.com` | `h2` |

`auto` tries QUIC first and falls back to HTTP/2. `cloudflared`'s own prechecks
name the reachability requirements literally: `Allow outbound QUIC traffic on
port 7844 or use HTTP2.` and `Allow outbound TCP on port 7844.`
(`prechecks/probes.go:31-32`).

The edge's certificate chains to Cloudflare-internal CAs that are not in the
public trust store; `cloudflared` ships them in `tlsconfig/cloudflare_ca.go`,
and any reimplementation must add them or the handshake fails `UnknownIssuer`.

On the QUIC connection the **first bidirectional stream is the control plane**.
It is not prefixed with the per-request signature; it carries Cap'n Proto RPC
directly, and the client calls
`RegistrationServer.registerConnection(auth, tunnelId, connIndex, options)`
(`tunnelrpc/registration_client.go`, served from
`connection/quic_connection.go::Serve`). Every stream after that is an inbound
request from the edge.

## 3. Per-request stream framing

An inbound stream begins with a 6-byte signature, a 2-byte version and a Cap'n
Proto `ConnectRequest` carrying the destination URL, the connection type
(`Http` / `Websocket` / `Tcp`) and metadata (`HttpMethod`, `HttpHost`, and one
`HttpHeader:<Name>` entry per header). The client replies with the analogous
`ConnectResponse` (status + headers) and then the stream is a byte pipe. The
schemas are `schemas/quic_metadata_protocol.capnp` and `schemas/tunnelrpc.capnp`.

Both directions use the same metadata convention, and it is easy to get wrong:
the status goes in a bare `HttpStatus` entry and **every** header must be
`HttpHeader:<Name>` (`HttpHeader:Content-Type`, `HttpHeader:Set-Cookie`, ...).
An unprefixed key is silently dropped by the edge, which then synthesises its own
`Transfer-Encoding: chunked` framing and forwards no origin headers at all. The
name casing is not significant.

## 4. Measurements in a sealed sandbox

Measured on the host where `cfrs` was developed, using the route setup from
`sandhome` (no privilege, no pty, no `/etc/passwd`, `bind=unix`):

| probe | result |
| --- | --- |
| outbound TCP to `github.com:{22,53,80,7844,8080,8443}` | `connect: Permission denied` (`EACCES`, errno 13) |
| outbound TCP to any host `:443` | works |
| outbound TCP to `127.0.0.1:{22,53,3128,8080,8888,1080}` | `EACCES`, the filter is on the **port**, not the host |
| outbound TCP to `127.0.0.1:443` | allowed by the filter, `ECONNREFUSED`, no local proxy to `CONNECT` through |
| outbound UDP to edge `:7844` | works, `cloudflared` precheck: `QUIC connection successful` |
| TLS to the tunnel anycast on `:443` (SNI `h2.cftunnel.com`) | legacy `CN=ssl881653.cloudflaressl.com`, expired 2020, not the tunnel service |
| `bind(2)` `AF_INET` `127.0.0.1:0`, `0.0.0.0:0`, `[::1]:0` | `EACCES` |
| `bind(2)` `AF_UNIX` | works |
| `POST https://api.trycloudflare.com/tunnel` | HTTP 200, real hostname + credentials |

Egress policy differs by host. A stricter sandbox permits only an HTTP
`CONNECT` proxy on 80/443/8443/8080, has no working DNS, and refuses `bind(2)`
on `AF_INET`; section 8 measures the WARP path there.

The consequences are direct:

- The HTTP/2 transport is dead here (TCP 7844 blocked), and the tunnel service
  is not served on 443. **QUIC over UDP 7844 is the only viable transport** for a
  *direct* connection; `--transport warp` (section 8) carries the edge connection
  on TCP 443 instead, so the port filter stops being decisive.
  The `socat`-relay-plus-`HTTP CONNECT`-egress-proxy recipe does not apply:
  the connect filter rejects every non-443 port before a proxy could be reached,
  and there is no proxy on 443.
- No TCP listener can be created, so the origin must be `AF_UNIX`. `cloudflared`
  itself can only expose a unix origin through a config-file ingress
  (`service: unix:/path`); `--unix-socket` is mutually exclusive with the
  `--url` that triggers quick-tunnel mode, and quick-tunnel mode is only
  triggered by `--url` or `--hello-world`. `cfrs` sidesteps that by running the
  protocol itself.
- `cloudflared`'s built-in `--hello-world` origin binds TCP and therefore cannot
  start here. `cfrs`'s built-in origins (`hello_world`, `http_status:NNN`,
  `static:`, `spa:`, `metrics`, share sessions) run in-process and need no
  listener.
- The connect filter does **not** stop WebSocket upgrades, so the HTTP-only
  limit is removable even here, see section 7.

## 5. Reproducing the proof

`cfrs demo --exit-on-verify` does all of it: it serves a built-in origin, provisions
a quick tunnel against `api.trycloudflare.com` (443), registers over QUIC to the
edge (UDP 7844), then fetches the public
`https://<random>.trycloudflare.com` URL and checks the body. A run prints the
public URL, the edge POP, and `PROOF ... HTTP 200`.

The unix-origin path is checked separately by pointing the tunnel at a socket:

```sh
python3 /tmp/uo.py /tmp/uo.sock           # any HTTP server on AF_UNIX
cfrs tunnel --unix /tmp/uo.sock
curl -sS -i https://<random>.trycloudflare.com/hello
```

For comparison, the reference binary reproduces the transport finding but not
the unix origin:

```sh
# origin
python3 -m http.server 8080
# transport test (TCP 7844 blocked here, so QUIC is selected)
cloudflared tunnel --url http://127.0.0.1:8080
# with a unix origin, triggered through a config file:
printf 'ingress:\n  - service: unix:/tmp/origin.sock\n' > cf.yml
cloudflared tunnel --config cf.yml --url http://placeholder.invalid --protocol quic
```

## 6. The service layer

Everything above is the transport. On top of it `cfrs` implements the parts a
`cloudflared` user expects, plus the quickbridge session model:

- **Ingress.** Ordered rules matched by hostname (exact and single-label `*`)
  and path prefix, cloudflared-style YAML, per-rule `originRequest` options.
- **Origins.** HTTP/HTTPS, `AF_UNIX`, `unix+tls:`, raw TCP, static directories
  with SPA fallback, fixed status codes, hello world, Prometheus metrics.
- **HA.** `ha-connections` registers several QUIC legs with distinct
  `conn_index` values; each leg has its own reactor and reconnects with
  exponential backoff and `replace_existing`.
- **Sessions.** `share` serves an axum router for multipart uploads and streamed
  downloads, with a 6-digit PIN exchanged for a `cfrs_pin` cookie, an
  unguessable `/s/<token>/` path, size and file caps, and stop-after/idle
  controls. Proxy sessions are forwarded through the same raw HTTP path as any
  other origin, with the gate applied first.

## 7. Raw streams over the HTTP tunnel

A quick tunnel is HTTP, but the edge proxies WebSocket upgrades, and a WebSocket
is a bidirectional byte pipe with message framing. `cfrs` uses that to carry
anything:

- The origin exposes `/__cfrs/ws` (`Service::Forward`). The edge delivers the
  upgrade as `ConnectionType::Websocket`; the origin computes
  `Sec-WebSocket-Accept = base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`,
  answers `101`, and then treats the rest of the stream as WebSocket frames
  (`tokio-tungstenite`, server role).
- One WebSocket message maps to one write on the target stream, so framing and
  back-pressure survive.
- `cfrs connect` is the far side: it accepts local `tcp://`/`unix://`
  connections and opens one WebSocket per connection, then pumps bytes. This is
  the websocat / wstunnel model, and it is what makes `--forward` useful for
  SSH, databases, unix sockets and any other raw protocol.

Measured end to end through a live quick tunnel: a local unix socket carried an
HTTP GET and POST (including a 64 KiB body) to an origin `AF_UNIX` socket and
back, with byte-for-byte framing. The connect filter never sees a new port, so
this works in the sealed sandbox too.

## 8. Reaching the edge when 7844 is filtered: WARP

A direct connection uses QUIC on UDP 7844 and nothing else: the edge answers on
7844, and `:443` with SNI `h2.cftunnel.com` serves a legacy 2020 certificate
rather than the tunnel service. A host that filters 7844 cannot tunnel directly.

The edge connection can instead be *carried* over TCP 443. `cfrs --transport
warp` registers anonymously with Cloudflare WARP, opens a MASQUE (`CONNECT-IP`)
session over HTTP/2 on TCP 443, and dials the edge's QUIC connection inside it.
The host's own `connect()` never targets port 7844, and no kernel UDP socket is
needed either.

- Registration is two HTTPS calls on 443: `POST /v0a5641/reg` creates the
  device, then `PATCH /v0a5641/reg/{id}` enrols a P-256 key and switches the
  device from `wireguard` to `masque`. The device document names the MASQUE
  endpoint (`162.159.198.2:443`) and the addresses assigned to the tunnel
  (`172.16.0.2` and a `2606:4700:110:...` v6 address).
- The session is an HTTP/2 `CONNECT` with `cf-connect-proto: cf-connect-ip` (the
  h2 spelling, not the HTTP/3 `:protocol` pseudo-header). Its data frames carry
  raw IP packets. `smoltcp` above it owns the assigned address and runs TCP and
  UDP.
- The QUIC endpoint is built on a `quinn::AsyncUdpSocket` whose datagrams are
  written to a UDP socket inside the MASQUE session. There is no local relay and
  no kernel socket: `quinn` hands a datagram to the adapter, the adapter hands
  it to `smoltcp`, and the packet leaves the host on TCP 443.

Measured in a sealed sandbox whose only egress is an HTTP `CONNECT` proxy on
80/443/8443/8080, with no working DNS and with `bind(2)` on `AF_INET` refused:

- `cfrs warp register` created a device, enrolled `secp256r1`, and reported
  `tunnel masque`, `ipv4 172.16.0.2`, `masque 162.159.198.2:443`.
- `cfrs warp probe --target 1.1.1.1:443,198.41.192.167:7844` opened the session
  through the proxy and reached both targets: 83 ms and 129 ms.
- `cfrs tunnel --hello-world --transport warp` discovered the edge by DoH
  (`198.41.200.73:7844`), completed the QUIC handshake through WARP, registered
  at colo `bom12`, and fetched its public URL for HTTP 200.

The host opened no socket to 7844. The only host egress was the proxy on TCP
443. The tunnel path and `cfrs warp probe` both use the library types
`WarpClient`, `WarpStack` and `warp::quic::endpoint`.
