# Edge protocol and WARP protocol

This document gives the wire behaviour that `cfrs` uses. The reference is
`cloudflared` (`github.com/cloudflare/cloudflared`). File names in this
document are paths in that repository.

## 1. Quick-tunnel provisioning

A quick tunnel starts with one HTTPS request
(`cmd/cloudflared/tunnel/quick_tunnel.go`):

```text
POST https://api.trycloudflare.com/tunnel
Content-Type: application/json
User-Agent: cloudflared/<version>
```

The body is empty. A good answer is:

```json
{"success":true,"result":{
  "id":"<uuid>","name":"qt-...","hostname":"<random>.trycloudflare.com",
  "account_tag":"<hex>","secret":"<base64, 32 bytes>"},"errors":[]}
```

`id`, `account_tag` and `secret` are the `TunnelAuth` credentials for the
registration. `--service-url` changes the endpoint. The request goes on TCP
443 and uses `HTTPS_PROXY` when it is set.

`cfrs` does not log the answer body when it cannot decode it, because the body
contains the tunnel secret.

## 2. Edge discovery

The edge addresses come from the SRV record
`_v2-origintunneld._tcp.argotunnel.com`. The targets are
`region1.v2.argotunnel.com` and `region2.v2.argotunnel.com`, port 7844
(`edgediscovery/allregions`).

`cfrs` tries these sources in sequence:

1. DNS over HTTPS (the JSON API of `cloudflare-dns.com`). This works on hosts
   that have no DNS resolver but have HTTPS egress.
2. The system resolver, then DNS over TLS.
3. A static list of edge addresses.

`CFRS_EDGE=ip:port,ip:port` replaces discovery.

## 3. Transports

| Protocol | Socket | TLS SNI | ALPN |
| --- | --- | --- | --- |
| QUIC | UDP 7844 | `quic.cftunnel.com` | `argotunnel` |
| HTTP/2 | TCP 7844 | `h2.cftunnel.com` | none |

* The SNI and the ALPN of QUIC are different strings. If the ALPN value is
  sent as the SNI, the handshake completes key derivation and then stops.
* The edge certificate chains to Cloudflare roots that are not in public
  trust stores. The roots are in `src/cloudflare/cf-edge-roots.pem` (from
  `tlsconfig/cloudflare_ca.go`). Without them, TLS fails with `UnknownIssuer`.
* Port 443 of the edge does not serve the tunnel service: TLS there is
  TLS 1.2, and its chain does not end at the edge roots (section 6). So
  cfrs uses 7844 only, and carries the edge on TCP 443 inside WARP
  (section 5.3).

### 3.1 QUIC

The first bidirectional stream that `cfrs` opens is the control stream. It has
no preamble. It carries capnp RPC: `cfrs` calls
`RegistrationServer.registerConnection(auth, tunnelId, connIndex, options)`
(`connection/quic_connection.go`, `tunnelrpc/registration_client.go`). The edge
opens each later stream for one visitor request.

`cfrs` also serves a `CloudflaredServer` bootstrap object on the control
stream. The edge uses it as a liveness check. Without it, the edge marks the
tunnel offline and visitors get HTTP 530.

Registration features (`ClientInfo.features`): cfrs sends the default
list of cloudflared 2026.10.7 (`features/features.go`), which is
`support_datagram_v2` only (`schema::FEATURES`). cloudflared 2026.10.7
removes `serialized_headers`, `quick_reconnects`, `allow_remote_config`,
`support_quic_eof` and `management_logs` before it sends the list
(TUN-10904: the edge supports them with no flag), and also
`support_datagram_v3` and `support_datagram_v3_1`. cfrs does not send
`postquantum` (it uses a classical key exchange, section 6) or
`support_datagram_v3_2` (it carries no UDP or ICMP datagram of a visitor).
The answers of HTTP/2 always carry the serialized header (section 3.2).

cloudflared makes one connection for a quick tunnel (`ha-connections` is
set to 1 in `quick_tunnel.go`) and four for a named tunnel. cfrs makes two
by default for both (`--ha-connections`, 1 to 8). The extra connections are
for redundancy: each one registers with the edge, and the edge chooses the
connection of each visitor request. One request (one stream) uses one
connection, so `--ha-connections` does not make one transfer faster; it can
let more requests run at the same time on more connections.

### 3.2 HTTP/2

`connection/http2.go`. On the TLS connection, the edge is the HTTP/2 client and
`cfrs` is the HTTP/2 server. The edge opens a stream for each request.
`cfrs` classifies each stream from its headers, in this order:

| Condition | Type |
| --- | --- |
| `Cf-Cloudflared-Proxy-Connection-Upgrade: update-configuration` | configuration push |
| `Cf-Cloudflared-Proxy-Connection-Upgrade: websocket` | WebSocket |
| `Cf-Cloudflared-Proxy-Src` is not empty | TCP stream |
| `Cf-Cloudflared-Proxy-Connection-Upgrade: control-stream` | control stream |
| all other requests | HTTP |

* Control stream: `cfrs` sends status 200 and keeps the stream open. The
  request body and the response body carry the same capnp RPC as on QUIC.
* HTTP: the visitor headers are plain HTTP/2 headers. `cfrs` changes the
  request into the `ConnectRequest` of section 4 and serves it with the same
  service layer as QUIC.
* Response: the origin headers go in one header,
  `cf-cloudflared-response-headers`, as `base64(name):base64(value)` pairs with
  `;` between them (raw standard base64, no padding). The HTTP/2 rules for
  header values do not apply to that header. `content-length` is also sent as
  a plain header. `cf-cloudflared-response-meta: {"src":"origin"}` tells the
  edge that the origin answered. Status 101 becomes 200, because HTTP/2 has no
  101.
* WebSocket: `cfrs` adds `Connection: Upgrade` and `Upgrade: websocket` for the
  origin, because HTTP/2 has no upgrade headers.
* Configuration push: `cfrs` answers `{"lastAppliedVersion":N,"err":null}`
  with the version of the push.

`tools/check-header-oracle.sh` compares the header encoding of `cfrs` with the
Go function `SerializeHeaders` of cloudflared.

### 3.3 Leg order

`--protocol auto --transport auto` tries QUIC, then HTTP/2, then QUIC through
WARP (section 5). The attempts are real registrations, in a staggered race
(`src/race.rs`, `--leg-failover staggered`, the default):

* The next leg starts when the leg before has not registered in 2 seconds,
  or at once when it fails. A filtered port does not answer, so a host that
  drops UDP and TCP 7844 starts WARP after about 4 seconds, not 16.
* The first leg that registers stays. When two legs register in the same
  turn, the earlier leg of the order stays. Each other leg that registered
  gets the unregister call, and then its connection closes. The legs that
  still run are cancelled.

`--leg-failover serial` starts a leg only after the one before failed, with
a time limit of 8 seconds for each attempt when another leg can follow.

UDP (`CFRS_UDP`, `src/udp.rs`): with `probe` (the default) and
`--protocol auto`, cfrs sends one QUIC packet with a reserved version (RFC
9000 section 15) to an edge address on UDP 7844 while the quick tunnel is
provisioned. The result is answered (a datagram came back), refused (the send
failed, or an ICMP error came back on the connected socket) or unknown (no
answer in 150 ms). Only refused removes the QUIC leg; unknown and answered
keep the order. A bind alone never gives answered. `CFRS_UDP=off` removes the
QUIC leg; `CFRS_UDP=on` sends no probe. `cfrs net doctor` sends the same
packet with a deadline of 3 s.

The stagger is not a probe: each leg is a full attempt on its own port and
protocol. `cfrs` does not probe TCP 7844 to select a leg, because a firewall
can close TCP 7844 and keep UDP 7844 open. Inside a leg, the HTTP/2 dial
starts the next edge address 250 ms after the one before (RFC 8305).

## 4. Stream framing (QUIC)

A visitor stream starts with a 6-byte signature (`0A 36 CD 12 A1 3E`), the
2-byte version `01`, and a capnp `ConnectRequest`:

* `dest`: the URL (HTTP and WebSocket) or `host:port` (TCP).
* `type`: `http`, `websocket` or `tcp`.
* `metadata`: `HttpMethod`, `HttpHost`, and one `HttpHeader:<Name>` entry for
  each header value.

`cfrs` answers with the same preamble and a capnp `ConnectResponse` (`error`,
`metadata`). After that, the stream is a byte pipe. The schemas are in
`src/cloudflare/schemas/`. `src/cloudflare/capnp.rs` implements the Cap'n
Proto encoding and `src/cloudflare/rpc.rs` the RPC subset (section 3.1).

In the response metadata, the status is the entry `HttpStatus`. Each header
must be an entry `HttpHeader:<Name>`. The edge drops a key without the prefix.
Then it makes its own chunked framing and sends no origin headers.

## 5. WARP

### 5.1 Registration

The API is `https://api.cloudflareclient.com/v0a5641`. All calls use the
headers `User-Agent: WARP for Android` and `CF-Client-Version: a-6.38.9-5641`.

| Call | Use |
| --- | --- |
| `POST /reg` | Make a device. The answer has the device `id` and a bearer `token`. |
| `PATCH /reg/{id}` | Enrol a P-256 key (X.509 SPKI, base64), `key_type: secp256r1`, `tunnel_type: masque`. |
| `GET /reg/{id}` | Read the device. |
| `GET /reg/{id}/account` | Read the account: type, WARP+ state, quota. |
| `PUT /reg/{id}/account` | Attach a license key: `{"license":"..."}`. |
| `DELETE /reg/{id}` | Remove the device. |

Only the answer to `POST /reg` has the token. `cfrs` keeps it in the saved
identity file, because the other calls need it. A key rotation is a new
`PATCH /reg/{id}` with a new key.

The device record gives the MASQUE endpoint (for example `162.159.198.2:443`),
the public key of the endpoint, and the tunnel addresses (`172.16.0.2` and an
IPv6 address in `2606:4700:110::/48`).

### 5.2 MASQUE session

* TLS to the endpoint on TCP 443, SNI `consumer-masque.cloudflareclient.com`,
  ALPN `h2`. The client certificate is self-signed with the enrolled P-256 key.
  `cfrs` checks the server key against the key in the device record.
* One HTTP/2 extended `CONNECT` to `https://cloudflareaccess.com` with
  `cf-connect-proto: cf-connect-ip`.
* The DATA frames of that stream carry capsules (RFC 9297). Each IP packet is
  one capsule of type 0. The value is the bare IP packet, with no context
  ID before it (RFC 9484 puts a context ID of 0 there). cfrs writes and
  reads no context ID (`capsule::tests::a_data_capsule_has_no_context_id`).
  The tunnel MTU is 1280.
* The request headers: `cf-connect-proto: cf-connect-ip`,
  `capsule-protocol: ?1`, `pq-enabled: false` and an empty `user-agent`.
  The front door accepts them (measured, podssh issue 63, a run of cfrs).
* The server certificate is not publicly trusted: its root is
  `CN=2024-02-27 Self-Signed Root, O=Cloudflare, Inc.` (measured, live run
  41268348982, `cfrs doctor`). Its key is byte for byte the SPKI of the
  `PATCH` answer, which is what cfrs pins (measured, podssh issue 63).
* A client certificate that does not match the enrolled key gives a TLS
  alert, not an HTTP status (measured, podssh issue 63). cfrs reports it as
  "TLS alert from the peer" (`hop::tls_text`).
* The `PATCH` answer lists the endpoint ports
  `[443, 500, 1701, 4500, 4443, 8443, 8095]` (measured, podssh issue 63).
  cfrs uses 443 only (`register::MASQUE_PORT`).
* The newer L4 proxy mode of the front door is HTTP/3 only (read, podssh
  issue 63). cfrs uses CONNECT-IP over HTTP/2.
* `smoltcp` owns the tunnel address and runs TCP and UDP on it. This is
  `cfrs::warp::WarpStack`.

### 5.3 The edge through WARP

`cfrs::warp::quic::endpoint` makes a `quinn::Endpoint` whose UDP socket is a
UDP socket of the `WarpStack`. The QUIC connection to the edge (UDP 7844) thus
goes inside the MASQUE session. The host opens only TCP 443.

### 5.4 Limits

* A proxy that terminates TLS (and makes a new TLS connection with its own CA)
  cannot carry the MASQUE session, because the session needs the client
  certificate and the pinned server key. The registration calls still work
  through such a proxy.
* The WARP proxy of `cfrs` (`cfrs warp proxy`) carries TCP (SOCKS5 and HTTP
  `CONNECT`) and UDP (SOCKS5 UDP ASSOCIATE). It resolves names through the
  tunnel. The UDP relay socket of an association is on `127.0.0.1`.

## 6. Edge, measured

Each row has a mark: **measured** (a command ran, with its date and run),
**read** (from the source of cloudflared 2026.10.7 or from a document) or
**inferred**. The tool is `tools/edge-facts.sh`; `.github/workflows/live.yml`
runs it on each push and each day (step "Edge facts"). The rows below are
from run 41268348982 (2026-11-01, a GitHub runner, ubuntu-24.04), address
198.41.192.107. Its exit code is 1 when one of the two facts that cfrs needs
is not true (the rows marked *need*).

| Fact | Result | Mark |
| --- | --- | --- |
| SRV `_v2-origintunneld._tcp.argotunnel.com` | `1 1 7844 region1.v2.argotunnel.com.` and `2 1 7844 region2.v2.argotunnel.com.` | measured |
| Addresses of `region1.v2.argotunnel.com` | 10: 198.41.192.7, .27, .37, .47, .57, .67, .77, .107, .167, .227 | measured |
| Addresses of `region2.v2.argotunnel.com` | 10: 198.41.200.13, .23, .33, .43, .53, .63, .73, .113, .193, .233 | measured |
| *need*: TLS on TCP 7844, SNI `h2.cftunnel.com`, no ALPN | TLS 1.3, X25519, verified against `cf-edge-roots.pem`, 31 ms | measured |
| SNI `probe.cftunnel.com`, `region1.v2.argotunnel.com`, or no SNI | Each: TLS 1.3, verified, 20 to 29 ms | measured |
| ALPN `h2` offered | The edge selects no ALPN | measured |
| Key group X25519 only; P-256 only | Both work; no post-quantum group is needed | measured |
| Issuer of the edge certificate | `OU=CloudFlare Origin SSL ECC Certificate Authority, O=CloudFlare, Inc.` (`cfrs doctor`) | measured |
| TCP 443 and 8443 of the edge address | TLS 1.2; the chain does not verify against the edge roots | measured |
| TCP 80 of the edge address | Not TLS | measured |
| *need*: the first bytes after the handshake on 7844 | `PRI * HTTP/2.0`: the edge is the HTTP/2 client | measured |
| UDP 7844, one QUIC packet with a reserved version | A version negotiation of 27 bytes (`cfrs doctor`) | measured |
| Latency from the runner to the edge, TCP | best 6.2 ms, median 7.2 ms (`cfrs doctor`, 9 samples) | measured |
| cloudflared and `HTTPS_PROXY` | Two requests for a proxy for the edge, cloudflare/cloudflared#350 and #1025, are closed (2023-09-05). cfrs uses the proxy for each TCP connection (section 1, `src/egress.rs`) | read |
| The prechecks of cloudflared | They use the name `probe.cftunnel.com` and test DNS, QUIC, TCP and TLS to both regions, and `api.cloudflare.com:443` | read (podssh design notes, cloudflared 2026.10.6) |

`cfrs doctor` measures the same path on any host, through its proxy.

## 7. Limits of quick tunnels

From the Cloudflare page
[Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)
(read 2026-11-01):

* Quick tunnels are for testing and development. For production, use a
  named tunnel (`--token` or `--config` with `credentials-file:`).
* No uptime guarantee.
* At most 200 requests in flight for each quick tunnel. More get `429`.
* No Server-Sent Events (SSE).

cloudflared makes one edge connection for a quick tunnel (section 3.1).

## 8. Terms

These documents apply. This section gives facts, not legal advice.

* Quick tunnels: the disclaimer of cloudflared 2026.10.7
  (`cmd/cloudflared/tunnel/quick_tunnel.go`) says that account-less
  tunnels "are subject to the Cloudflare Online Services Terms of Use
  (https://www.cloudflare.com/website-terms/)", and that Cloudflare may
  investigate the use of tunnels for violations of those terms.
* WARP: the Application Terms of the WARP client license "the
  Application", and forbid reverse engineering of it. Cloudflare may
  "block certain kinds of usage" (read, podssh design notes). cfrs is a
  separate program: it contains no code of the WARP application, and it
  uses the public registration API of section 5.1.

## Failure causes

The error line of cfrs names the hop that failed, and a second line says
what may help. The failure report (`CFRS_ERROR_PROGRAM`) has the hop in
`hop`. The text of a peer (a proxy reply, an edge reason) is kept, with no
control characters.

| Hop | Example cause | cfrs does | What may help |
| --- | --- | --- | --- |
| `proxy` | `403 Forbidden: not on the egress allowlist`, 407 with NTLM | Stops the attempt; another leg can follow | Fix the proxy URL or its allow-list; `--no-proxy` |
| `dns` | No resolver answers, DoH blocked | Tries the system resolver, then DoH by IP address | `--resolve HOST=IP`; `socks5h://` |
| `tls` | `UnknownIssuer`, `TLS alert from the peer: HandshakeFailure`, an expired certificate | Stops the attempt | `--ca-file` for a TLS-inspecting proxy; check the clock |
| `edge-register` | A refusal with `should_retry = false` (bad token, deleted tunnel) | Stops the leg; does not retry | Check the token, or use a quick tunnel |
| `edge-register` | A refusal with `retry_after` | Retries after `retry_after` (1 s to 300 s) | Nothing |
| `edge-stream` | No PING answer, GOAWAY, a lost connection | Connects again at once, then with backoff and jitter, with no limit | `--transport warp` on a host with only TCP 443 |
| `origin` | Connection refused | Answers the visitor with 502 | Start the origin; check `--url` |

`scripts/soak.sh` runs N quick tunnels end to end, keeps one log for each
trial, and prints the failure rate.
