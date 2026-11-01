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
* Port 443 of the edge does not serve the tunnel service.

### 3.1 QUIC

The first bidirectional stream that `cfrs` opens is the control stream. It has
no preamble. It carries capnp RPC: `cfrs` calls
`RegistrationServer.registerConnection(auth, tunnelId, connIndex, options)`
(`connection/quic_connection.go`, `tunnelrpc/registration_client.go`). The edge
opens each later stream for one visitor request.

`cfrs` also serves a `CloudflaredServer` bootstrap object on the control
stream. The edge uses it as a liveness check. Without it, the edge marks the
tunnel offline and visitors get HTTP 530.

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
  one capsule. The tunnel MTU is 1280.
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
