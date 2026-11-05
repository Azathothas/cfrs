# podnet capability study: router, file server, file transfer, git hosting

Scope: what `cfrs` (tree at `3bed023`, v0.3.0-beta.12 + 4 commits) already has
for each role, the minimal viable feature set of each role, the gaps, a CLI
shape, the modules, the tests and a size estimate. Constraint: one static musl
binary, no root, no CAP_NET_ADMIN where possible. Read only; nothing was built.

Reference numbers:

* Static release binary v0.3.0-beta.12: `cfrs-x86_64-unknown-linux-musl`
  18 465 888 bytes, aarch64 15 692 296 bytes; `pod-netns` 1.5 MB.
* `src/main.rs` is 7 103 lines. Each new verb below goes into its own module,
  not into `main.rs`.

## 0. Verdict

| Role | Today | Minimal gap | New crates | Size (Rust lines incl. tests) |
| --- | --- | --- | --- | --- |
| Router (L4, no root) | All parts exist as separate commands; composition works today (`warp proxy` + `pod --serve -x/-r`) | One process with named networks, groups (weighted, health-checked, kill switch), per-door default network, generic `-L` | none | ~2 500 |
| File server | `serve` (static, single Range, no listing), `serve --local`, `share` (upload / one-file download / proxy, PIN) | Directory listing, auth on `--local`, read/write roles, PUT + multipart upload into the tree, tar of a directory | none | ~1 500 |
| File transfer | `share` over a quick tunnel (URL + PIN, Cloudflare sees plaintext), relay pair/node/connect (byte pipe, long tokens, 64 MiB cap) | Short code + PAKE, end-to-end AEAD, raced roads (relay, tunnel, transit, LAN), resume over the 64 MiB relay cap, dirs | SPAKE2 (optional: own code); SecretBox only for wormhole wire interop | ~3 000 (or port ~2 800 from podssh) |
| Git hosting | Nothing server-side. Client side only (`warp nc`, `warp ssh-config`, `doctor --agent`) | Smart HTTP (CGI to `git http-backend`), SSH (russh server, already compiled in), auth, repo mapping | none (runtime needs the `git` program) | ~2 200 |

Recommendation: build five small shared enablers first (section 6), then the
file server (smallest, no new deps), then git hosting, then the router, then
file transfer (largest; depends on the resumable relay layer).

## 1. Inventory of the existing pieces

### 1.1 Inbound: expose a local service

| Piece | Path (lines) | What it gives | Limits |
| --- | --- | --- | --- |
| `tunnel --url/--port/--unix/--tcp/--forward/--config` | `src/tunnel.rs` (1599), `src/proxy.rs` (2034), `src/ingress.rs` (580), `src/cloudflare/` | Quick or named Cloudflare tunnel; ingress rules by host and `path:` regex; legs quic, http2, quic+warp, http2+relay (`--transport auto/direct/warp/relay`) | Edge takes at most 100 MB in one request body (free plan; `src/share.rs:57`). `--tcp` needs a cloudflared-style client at the visitor |
| `--auth-user` + `--auth-password-file` | check at `src/proxy.rs:137`, creds `src/proxy_auth.rs` (615) | HTTP Basic, one user, in front of each HTTP origin and `--forward` | Tunnel only: `serve --local` refuses it (`src/main.rs:3212`) |
| `tunnel --forward` + `connect -L` | `src/ws.rs` (596), `src/main.rs:779` (`ConnectArgs`) | TCP/unix stream over a WebSocket through the tunnel (wstunnel style), Basic auth in the upgrade | `connect` has `-L` listeners only (`required = true`); no stdin/stdout mode for an SSH `ProxyCommand` |
| `relay pair / node / connect / stop` | `src/relay_reverse.rs` (1139), `src/ws_relay.rs` (995), `src/relay_pool.rs` (380) | Reverse road of `tcp.ssh.relay.ajam.dev`: a node holds `/v1/node/NAME`, an operator opens `/v1/connect/NAME`; stdio (`ProxyCommand`) or `--listen` | One `--to` target (`Target::{Tcp,Unix}`, `src/relay_reverse.rs:230`); pair lasts 72 h; relay session cap 64 MiB both ways, 12 h, 180 s idle (podssh `docs/relay.md:498-526`); cfrs has no resumable layer (podssh has one, T-155) |
| `net proxy --forward VIRT=REAL`, `net switch` | `src/vnet/proxy.rs` (514), `src/vnet/switch.rs` (1072) | Virtual 10.66.0.0/24 network between hosts through a switch (unix, or TCP with token); a virtual address forwards to a real `host:port` or `unix:` | Switch link is not encrypted (doc says: carry it in `tunnel --forward`) |
| `agent up --expose PORT` | `src/agent.rs` (692), `src/main.rs:276` | Detached quick tunnel for each port, after the doctor | Quick tunnels only |
| `relay.rs` (SSH `-R` to pinggy) | `src/relay.rs` (668) | russh client, remote forward from `free.pinggy.io:443` to a unix origin | Library only; no CLI uses it (only `feature::ShareLink::from_relay`, `src/feature/mod.rs:1263`) |

### 1.2 Outbound: networks that a flow can leave through

| Network | Path | Entry points |
| --- | --- | --- |
| WARP (MASQUE h2/h3, WireGuard, carry) | `src/warp/` (session.rs 1211, ip.rs 1680 smoltcp stack, proxy.rs 1991) | `warp proxy`, `warp forward -L`, `warp nc`, `warp run/exec/shell` (pod), `warp tun` (needs CAP_NET_ADMIN), `warp up` |
| Several WARP devices in one process | `warp proxy --listen-identity LISTEN=PATH` (`src/main.rs:4340`) | One listener for each device: the base of a userspace multi-WAN |
| Relay forward road | `src/ws_relay.rs:428` `Relay::connect(SocketAddr)` | `warp nc --via-relay`, the http2+relay edge leg, MASQUE through the relay | Public IPv4 TCP only, 64 MiB / 12 h per session |
| Egress proxy | `src/egress.rs` (1707): `dial` (`:1003`), `Carrier::{Tcp,Unix,Exec}` (`:54`) | `--proxy`, `HTTPS_PROXY`, `NO_PROXY`; HTTP CONNECT (Basic, Digest), SOCKS5/5h, `socks5h+unix:`, `http+exec:CMD` | One hop per process; `http+exec:` can chain to another program |
| pod-netns upstream chain | `crates/pod-netns/src/upstream.rs` (1040): `select_chain` (`:334`), `connect_upstream_async` (`:370`) | `-x` repeatable (SOCKS5 hops chain), `socks5://unix:`, `http://unix:`, `tailscale:SOCK`, `direct`; `-r domain:/cidr:=PROXY` |
| Tailscale (unmodified tailscaled, LocalAPI `/localapi/v0/dial`) | `crates/pod-netns/src/tailscale.rs` (556) | `net tailscale` front door, `pod -x tailscale:SOCK` | Needs an external `tailscaled --tun=userspace-networking` |
| Virtual network | `src/vnet/` | `net proxy` front door into the smoltcp stack | |
| Direct | `egress::dial_direct` (`src/egress.rs:1022`) | `warp proxy -r ...=direct`, pod `=direct` | |

### 1.3 Front doors (SOCKS5 / HTTP CONNECT)

One parser (`pod_netns::socks`, 746 lines; `src/vnet/mod.rs:53` re-exports it),
but four accept loops with their own dial side:

| Front door | Path | Network | Extras |
| --- | --- | --- | --- |
| `warp proxy` | `src/warp/proxy.rs` | WARP | UDP ASSOCIATE (`:825`), `--dns`, rules `tunnel/direct/reject` (`src/warp/rules.rs`, 430), `--rules-file` reload, proxy auth, `--l4` |
| `pod --serve LISTEN -x ...` | `crates/pod-netns/src/frontdoor.rs` (272), help `cli.rs:96` | Any `-x` chain, `-r` rules | UDP ASSOCIATE; field report: "clean way to get a host-wide SOCKS" |
| `net proxy` | `src/vnet/proxy.rs` | Virtual network | `--map`, `--import`, `--control` |
| `net tailscale` | `crates/pod-netns/src/tailscale.rs` | Tailnet | Default `unix:/tmp/cfrssocks.sock` |

L3 capture of a program with no root: `pod` backends netns, netns-raw, seccomp
(`crates/pod-netns/src/{netns.rs 1199, raw.rs 436, seccomp.rs 1900}`).
`warp run --backend netns-raw` sends raw packets of a namespace through WARP
(TCP, UDP, ICMP, IPv6). The LD_PRELOAD shims (`shim/*.c`, `src/vnet/shim.rs`)
compile C with the host `cc` at run time and do not reach static programs.

### 1.4 HTTP services

| Piece | Path | Behaviour |
| --- | --- | --- |
| `serve --dir` (tunnel) and `serve --local ADDR` | `src/main.rs:3187`, `:3209`; router `src/service.rs:110` `static_router` | `tower_http::ServeDir`: GET/HEAD, single Range (a multi-range gets 200 full, `src/service.rs:172-180`), Last-Modified/If-Modified-Since, `index.html` on directories, `--spa`. Guard `static_guard` (`:168`): no dot segment, real path in the root, regular file or directory only. No directory listing (a directory with no index gives 404, `Show::root_404`). No auth on `--local`. No upload |
| `share --mode upload` | `src/share.rs:302` `upload_router`, `:605` `upload_receive` | Multipart form, files mode 0600, unique names, limits: 512 MiB per file, 32 files, 4 GiB per session, `--max-request` 100 MB (413 before the body). Random token in the path |
| `share --mode download` | `src/share.rs:835`, `:899` | One regular file only (no directory, no stdin; the "clipboard" in the module doc is stale), single Range resume with If-Range/ETag (`parse_range` `:1020`), `--stop-after` |
| `share --mode proxy` | `src/service.rs` `Built::ShareProxy` | Gated forward to a local HTTP port or unix socket; PIN always on |
| PIN gate | `src/gate.rs` (478) | 6 digits, cookie `cfrs_pin`, `POST /__cfrs/unlock`; after `MAX_FAILURES` = 10 wrong codes no code opens it |
| Built-in service dispatch | `src/proxy.rs:238` (`Built::Static`), `:429` `dispatch_axum` | Any axum `Router` behind the tunnel; the request body streams (pump, `:477`), so a new router (git, files) plugs in as one `Built` variant |
| Library duplicates | `src/origin/static_files.rs` (608, `StaticDir`, ETag 304, no Range), `src/feature/mod.rs` (2139: `StaticServer` `:1049`, `StaticResponse` `:940`, `AccessController` `:414`) | Not used by any CLI command (only `util/http.rs` refers to them). Public library API (ruling of 2026-11-04, #276): keep them |

### 1.5 SSH pieces

* `russh 0.64` with `default-features = false, features = ["ring"]`
  (`Cargo.toml`). No `rsa` feature: RSA keys are not supported.
* Used only as a client: `src/relay.rs` (pinggy `-R`), `src/transport/ssh.rs`
  (342, `SshRelay` transport; the doc notes that free relays fake
  `direct-tcpip`), `examples/edge_probe.rs` (276). None is wired to a CLI
  command.
* The server module (`russh::server`: `auth_none`, `auth_publickey`,
  `exec_request`, `env_request`, `channel_open_direct_tcpip`,
  `tcpip_forward`) is compiled into the crate with no extra feature. It is not
  linked today because nothing calls it.
* `ssh-key 0.7.0-rc.11` (default features: std) has
  `ssh_key::AuthorizedKeys` to parse an `authorized_keys` file.
* SSH client-side helpers: `warp nc` (ProxyCommand through WARP or the
  relay), `warp ssh-config` (`src/warp/ssh_config.rs`, 376, owns a block in
  `~/.ssh/config`), `doctor --agent` (`src/agent.rs`: git over HTTPS and SSH
  checks), `net ts-shims` (`src/vnet/tailscale_ssh.rs`, user table shims for
  Tailscale SSH).

### 1.6 Process management (all roles reuse these)

* `--detach`, `ps`, `stop`, `logs`, `wait`: `src/detach.rs` (1210),
  `src/instances.rs` (636). Supervisor with backoff; secrets in
  `NAME.secrets` (0600).
* `autostart add/remove/list/run`: `src/autostart.rs` (791), systemd user unit
  or crontab `@reboot`, secrets in an env file.
* `agent up/down/status`: `src/agent.rs`.
* Socket rule (ruling 2026-11-04): live socket = exit 69, non-socket file =
  64, stale socket removed (`net::claim_socket_path`,
  `pod_netns::listen::bind_private`).

## 2. Router

### 2.1 Minimal viable feature set

1. Named networks: `warp[:IDENTITY]`, `relay[:URL]`, `proxy:URL` (egress
   chain), `tailscale:SOCKET`, `switch:ADDR` (vnet), `direct` (LAN/host).
2. Groups of networks: weighted per-flow selection, TCP health check through
   each member (connect to `HOST:PORT` every N s, M misses to fail), failover,
   kill switch (reject, no leak to `direct`). This is the userspace form of
   the mwan lessons (attachment `mwan/README.md`: TCP checks because "ICMP
   yes, TCP no"; kill switch). Per-flow balancing aggregates parallel flows,
   not one flow.
3. Front doors: SOCKS5 + HTTP CONNECT + UDP ASSOCIATE (+ optional DNS) on a
   TCP or unix listener, each with a default network or group (the userspace
   form of "source rules").
4. Policy rules: `domain:` / `cidr:` -> network, group or `reject`, first
   match wins, file reload.
5. Port forwards: `-L LISTEN=NETWORK:HOST:PORT` for each network (today WARP
   only: `warp forward`, `src/warp/forward.rs`, 203).
6. Expose: one verb over the existing inbound paths (tunnel, relay node,
   switch).
7. Status: per network health, flow counters, bytes (`src/metrics.rs`,
   `src/decisions.rs` exist).

### 2.2 Have / missing

* Have: every network adapter (1.2), every front door (1.3), the rule
  matcher (`pod_netns::RuleMatch`, shared with `src/warp/rules.rs`), several
  WARP devices in one process, L3 capture of programs (pod), inbound paths
  (1.1). A router works today by composition:
  `warp proxy --listen unix:/a.sock --listen-identity unix:/b.sock=warp-b.json`,
  then `pod --serve tcp://127.0.0.1:1080 -x socks5h://unix:/a.sock
  -r domain:.corp=tailscale:/ts.sock -r cidr:10.0.0.0/8=direct`.
* Missing:
  * A `Dialer`/`Network` trait over the five dial functions
    (`egress::dial`, WARP `dial`/`dial_ips` in `src/warp/proxy.rs`,
    `Relay::connect`, tailscale dial, vnet stack). The accept loops in 1.3
    each hard-code one network.
  * Groups, health checks, failover, kill switch (nothing exists).
  * The relay as a network for a front door (only `warp nc --via-relay`).
  * `warp proxy` rule actions are `tunnel/direct/reject` only; no action
    "via another network".
  * Generic `-L` for each network; UDP forwards; DNS front door for a
    network other than WARP (`--dns` is WARP only).
  * One config file and one process; `podnet route status`.
  * `warp forward --list` / forwards in `ps`, `--resolve` on forward
    (field report items 4 and 5).
* Root-only (keep optional, do not make it the default): kernel multi-WAN
  (ECMP tables, nft masquerade) as in mwan. podnet can emit its JSON
  (`route export --format mwan-json`, FR item 4) for `warp tun` WANs.

### 2.3 CLI shape

```sh
podnet route [--config FILE]
    --net warp=warp                      # default identity
    --net warp2=warp:/state/warp-b.json  # second device
    --net up=proxy:http://proxy:3128 --net relay=relay --net lan=direct
    --net corp=tailscale:/run/tailscale/tailscaled.sock
    --group wan=warp*2,warp2*1,relay*1 --check wan=tcp://1.1.1.1:443,every=5s,misses=3
    --door tcp://127.0.0.1:1080=wan --door unix:/run/podnet/corp.sock=corp
    -r domain:.corp.example=corp -r cidr:10.0.0.0/8=lan --rule-default wan
    -L 127.0.0.1:2222=corp:git.corp:22
    [--detach --name router]
podnet route status [--json]
podnet route export --format mwan-json
podnet forward -L LISTEN=NET:HOST:PORT ...      # generic; `warp forward` stays as an alias
podnet expose TARGET --via tunnel|relay|switch  # alias over tunnel / relay node / net proxy --forward
```

Config file: the same keys as the flags. Use the YAML reader in-tree
(`src/yaml.rs`, 530) or `serde_json` (in-tree); no new format crate.

### 2.4 Modules

* `crates/podnet-core/src/net/` (core crate of the rename): `Network` trait
  (`dial_tcp`, `udp`, `name`), `Group` (weights, health, kill switch),
  rule engine (move `RuleMatch` + `select_chain`), front door (generalize
  `crates/pod-netns/src/frontdoor.rs` to take `Arc<dyn Network>`).
* Adapters implement `Network`: `src/warp/` (WarpStack), `src/relay/`
  (forward road), `src/egress.rs`, tailscale (pod-netns), `src/vnet/`,
  direct.
* `src/route/` in the binary: CLI, config, status.

### 2.5 Tests

* Unit: weighted pick with a seed, health state machine (miss/recover),
  kill switch, rule -> group resolution, config parse errors.
* Loopback (unix sockets only, so the `restricted-host` CI job runs them):
  two in-process fake SOCKS5 upstreams; flows split by weight; one upstream
  closes -> flows fail over; both close -> reject; `-L` over a unix listener.
  TCP-listener tests start with `need_loopback!()`.
* `live.yml` step "podnet route: WARP + relay + direct": door on TCP; curl
  `http://1.1.1.1/cdn-cgi/trace` gives `warp=on` through `warp`,
  `warp=off` through `relay`; drop TCP 443 to the MASQUE front door with
  iptables (the live job already drops UDP 7844) -> group fails over to
  relay; restore. A second WARP device conflicts with the ruling "do not
  register WARP devices when it is not necessary" (owner question).

### 2.6 Size

~2 500 lines (trait + adapters 600, groups/health 400, config 300, CLI 300,
tests 800). No new crate. Binary +100-200 KB.

## 3. File server

### 3.1 Minimal viable feature set

GET/HEAD, single Range, ETag/Last-Modified, directory listing (HTML and
JSON), hidden dotfiles and no symlink escape, auth with read and write roles
(Basic users, optional PIN gate, optional token path), uploads into the tree
(PUT `curl -T` and multipart form) with limits and atomic rename, tar download
of a directory, served locally (TCP or unix) and publicly (tunnel or relay).

### 3.2 Have / missing

* Have: static serving with the guard, Range, conditional GET, SPA
  (`src/service.rs`); local TCP/unix listener (`serve --local`); public
  serving through each tunnel transport; Basic auth through the tunnel; the
  upload engine with limits and 0600 files (`share` upload); one-file
  download with Range resume and PIN (`share` download); relay exposure by
  composition (`serve --local unix:/s.sock` + `relay node --to unix:/s.sock`
  + `relay connect NAME --listen tcp://127.0.0.1:8080`).
* Missing: directory listing; auth on `--local` (refused at
  `src/main.rs:3212`); more than one user, read/write roles; PIN for
  `serve`; uploads into the served tree (PUT, multipart); tar of a directory;
  `share --local` (share has no local listener); a directory in `share
  --mode download`.

### 3.3 CLI shape

```sh
podnet serve DIR [--local ADDR]... [--via tunnel|relay|none]
             [--list] [--upload[=SUBDIR]] [--max-upload BYTES] [--tar]
             [--auth-user U --auth-password-file F | --users FILE | --pin]
             [--anon-read] [--spa] [--detach]
podnet share ...   # unchanged (one-shot sessions)
```

`--users FILE`: lines `USER:ROLE:PASSWORD-HASH` or `USER:ROLE` with a
password file; roles `read`, `write`.

### 3.4 Modules

`src/files/`: `static.rs` (move `static_router`, `static_guard`),
`listing.rs` (HTML with `gate::escape_html`, JSON), `upload.rs` (move the
streaming core of `share::upload_receive`; PUT to a temp file + rename),
`tar.rs` (ustar writer, shared with transfer), `auth.rs` (axum middleware
over `proxy_auth::Credentials` and `gate::Gate`, so the same check works on
`--local`, the tunnel and the relay). `service.rs` gets `Built::Files`.
`origin/static_files.rs` and `feature::StaticServer` stay (library API), and
can later call `files::`.

### 3.5 Tests

* `tower::ServiceExt::oneshot` tests: listing escapes a name with `<script>`,
  hides dotfiles and links out of the root, JSON listing; Range 206/416;
  PUT 201, PUT over the limit 413 with no partial file, PUT with `..` or a
  dot segment refused; no creds 401, read user PUT 403; tar entries equal the
  tree.
* A unix-socket `--local` server test (runs on `restricted-host`).
* `live.yml`: extend "Quick tunnel with --auth-user": `serve --list
  --upload --users`; curl the listing, a Range, a 1 MiB PUT, a 401; then the
  relay composition (node + connect + curl).

### 3.6 Size

~1 500 lines (listing 250, upload 200, auth 200, tar 150, CLI 100, tests
600). No new crate. Binary +50 KB.

## 4. File transfer

### 4.1 What exists today

| Path | Use as transfer | Limits |
| --- | --- | --- |
| `share --mode download --file F --password --stop-after` | One-shot send to a browser or curl through a quick tunnel | Long URL; the PIN flow needs a cookie (awkward for curl); Cloudflare terminates TLS and sees the plaintext; one file; the sender needs an edge leg |
| `share --mode upload` | One-shot receive | 100 MB per request through the edge |
| `relay pair` + `relay node --to unix:S` + `relay connect NAME` | A byte pipe between two hosts behind NAT, both with outbound 443 only | Long name + connect token; no file protocol; relay sees the bytes unless the app encrypts; 64 MiB / 12 h / 180 s idle per session; no resume in cfrs |

croc / magic-wormhole give: short code, PAKE, end-to-end encryption, relay
fallback, directories, resume (croc), no account. cfrs gives the carriers but
none of the code, PAKE, end-to-end or resume parts.

### 4.2 Minimal viable feature set

`send PATH...` prints a short code; `receive CODE` gets the files. PAKE keys
the session; every carrier (mailbox, relay, Cloudflare, transit) sees only
ciphertext. Directories as a tar stream. SHA-256 check of each file. Resume
after a cut (and across the 64 MiB relay session cap). Both ends can be
443-only hosts behind an HTTP proxy. One guess for each code; the code is
never in argv (prompt or stdin).

### 4.3 Design

* Rendezvous: magic-wormhole mailbox protocol over a WebSocket on 443:
  `wss://relay.magic-wormhole.io/v1`, then
  `wss://mailbox.mw.leastauthority.com/v1` (podssh
  `crates/podssh-relay/src/code/mod.rs:40`), or a `/v1/mailbox` of the relay
  when its operator adds one (podssh relay role has it,
  `crates/podssh-relay/src/serve/mailbox/`).
* PAKE: SPAKE2 keyed by the code; then sealed phases carry the offer (names,
  sizes, hashes) and the road descriptors.
* Roads, raced:
  1. cfrs relay reverse road: the sender pairs, the connect token goes inside
     a sealed phase, data in AEAD records with offsets; a new session before
     60 MiB continues at the offset.
  2. Quick tunnel: the sender serves sealed chunks at a random path; the
     receiver GETs with Range (the 100 MB limit is for request bodies, not
     for downloads).
  3. LAN direct: when both ends can bind and connect (hints in the offer).
  4. Least Authority transit WebSocket `wss://relay.mw.leastauthority.com`
     (443; podssh `crates/podssh-relay/src/transit/mod.rs:37`).
* Reuse: podssh `crates/podssh-relay/src/code/` (1 824 lines: mailbox,
  SPAKE2 exchange, phrase, words, wormhole) and `src/transit/` (1 013 lines).
  podssh is 0BSD and of the same owner. Port them to cfrs's
  `tokio-tungstenite` + `rustls`/ring.

### 4.4 Dependencies

* SPAKE2, three choices: `spake2 0.4.0` (curve25519-dalek 4, sha2 0.10,
  hkdf 0.12: duplicates of the tree's 5 / 0.11 / 0.13;
  `deny.toml` has `multiple-versions = "warn"`); `spake2 0.5.0-pre.0`
  (2026-01-25; curve25519-dalek 5, sha2 0.11, hkdf 0.13, the tree's
  versions, but a prerelease); or own code on curve25519-dalek 5 (~250 lines,
  checked against the vectors of `spake2 0.4`).
* AEAD: ring ChaCha20-Poly1305 (in tree) for a podnet-native protocol.
  `crypto_secretbox` (XSalsa20-Poly1305, pure Rust, new) only for the wire
  format of magic-wormhole / podssh.
* Words: the PGP word list (~6 KB, embedded).

### 4.5 CLI shape

```sh
podnet send [--via auto|relay|tunnel|transit|lan] [--mailbox URL] [--words 3]
            [--text TEXT] PATH...      # prints: podnet receive 7-guitar-sunset-amber
podnet receive [--out DIR] [--yes] [--via ...]   # code from the prompt or stdin
```

### 4.6 Modules

`src/transfer/`: `code.rs` (nameplate + words), `pake.rs`, `mailbox.rs`,
`seal.rs` (AEAD records with offsets), `roads/{relay.rs,tunnel.rs,lan.rs,transit.rs}`,
`resume.rs`; `tar.rs` shared with `src/files/`. Needs enabler 6.5 (resumable
relay session).

### 4.7 Tests

* Unit: PAKE vectors; a wrong code fails at both ends and ends the code
  (one guess); tar round trip with odd names; AEAD record tamper fails.
* Loopback: an in-test mailbox stand-in (WebSocket server) and the fake relay
  of `tests/relay_reverse.rs` with a byte cap: a transfer larger than the cap
  completes by resume; the tunnel road against a local axum server.
* `live.yml`: send/receive a 100 MiB random file between two processes on the
  runner through the public mailbox and the real relay (crosses the 64 MiB
  cap), then with `--via tunnel`; compare SHA-256.

### 4.8 Size

~3 000 lines (code/words 150, PAKE 250, mailbox 350, seal 150, roads 600,
resume 200, CLI 200, tests 900), or a port of ~2 800 lines from podssh.
0-2 new crates. Binary +150 KB.

## 5. Git hosting

### 5.1 What exists today

Nothing server-side. Client side: `warp nc`, `warp ssh-config`, `doctor
--agent` (git over HTTPS and SSH checks). The russh server module is in the
dependency but unused. The field report (attachment `522011b9`) was a survey
of authless git hosting; it ran git over SSH and smart HTTP as a client
through WARP.

### 5.2 Minimal viable feature set

Smart HTTP: anonymous clone and fetch, authenticated push. SSH:
`git-upload-pack` (anonymous optional) and `git-receive-pack` with
`authorized_keys`. A repository root with path mapping that refuses `..` and
dot segments. `git init --bare` helper. Expose locally, through the tunnel,
or through the relay. Protocol v2.

### 5.3 Smart HTTP: three designs

| Design | How | New deps | Verdict |
| --- | --- | --- | --- |
| A. CGI to `git http-backend` | An axum router runs `git http-backend` (`tokio::process`, feature `process` is on) with `GIT_PROJECT_ROOT`, `PATH_INFO`, `REQUEST_METHOD`, `QUERY_STRING`, `CONTENT_TYPE`, `CONTENT_LENGTH` (unset for a chunked body: http-backend of git 2.19 or later reads to EOF; a test must confirm the minimum version), `GIT_HTTP_EXPORT_ALL` (or `git-daemon-export-ok`), `HTTP_GIT_PROTOCOL` (v2), `REMOTE_ADDR`, `REMOTE_USER` only after a good Basic check (http-backend then allows receive-pack). podnet answers 401 for `service=git-receive-pack` with no creds, so git prompts. http-backend inflates `Content-Encoding: gzip` (git gzips upload-pack bodies over 1 KiB). Parse the CGI head (`Status:`), stream the body both ways | none | Recommended |
| B. Spawn `git upload-pack/receive-pack --stateless-rpc [--advertise-refs]` | Own pkt-line `# service=` header; own gzip inflate | `flate2` + `miniz_oxide` (pure Rust; not in the tree today) | No gain over A |
| C. Native | `gix 0.90` has client-side protocol and pack code, no complete upload-pack/receive-pack server; large tree. `git2` = libgit2: a C build (zig cc can link it static), no server either; the crate declares `MIT OR Apache-2.0` but the bundled C library is GPL-2.0 with a linking exception (a legal check, not a `cargo deny` failure) | heavy | Not recommended |

The router plugs in as `Built::Git(Router)` in `src/service.rs`; the tunnel
dispatch streams it through `dispatch_axum` (`src/proxy.rs:429`), and
`--local` serves the same router with `axum::serve`.

### 5.4 SSH

`russh::server` (no new crate): ed25519 host key made once and kept in the
state directory (0600); `auth_publickey` against `ssh_key::AuthorizedKeys`;
`auth_none` -> read-only when `--anon-read`; `env_request` keeps
`GIT_PROTOCOL`; `exec_request` accepts only `git-upload-pack 'PATH'`,
`git-receive-pack 'PATH'`, `git-upload-archive 'PATH'`; spawn `git
upload-pack REPO` and pump stdin/stdout/stderr; `exit_status`. Refuse shell,
pty, `direct-tcpip` and `tcpip-forward` (a later router can use the last two:
`ssh -D/-L/-R` into podnet networks).

* RSA client keys need the russh feature `rsa` -> crate `rsa`, advisory
  RUSTSEC-2023-0071 (Marvin; it hits private-key operations, a server only
  verifies). `deny.toml` has `ignore = []`, so `cargo deny` fails without an
  explicit ignore. Owner decision; default: ed25519 and ECDSA only.
* Expose SSH: TCP listener (needs `bind`), unix socket + `relay node --to
  unix:` (works today), tunnel `--forward` WebSocket + a `connect --stdio`
  ProxyCommand (missing, enabler 6.1).

### 5.5 Limits to document

* Quick tunnel: at most 100 MB in one request body: a push of a larger pack
  over HTTP fails. Clones (response bodies) are not limited.
* Relay: 64 MiB per session and no resume in cfrs: an SSH clone or push over
  the relay larger than ~64 MiB fails until enabler 6.5 exists.
* Runtime: the `git` program (and `git-http-backend` in `git --exec-path`).
  The binary stays static; `podnet doctor` reports a missing git.

### 5.6 CLI shape

```sh
podnet git serve --root DIR [--local ADDR]... [--ssh LISTEN]... [--via tunnel|relay|none]
                 [--anon-read | --no-anon-read]
                 [--push-user U --push-password-file F | --users FILE]
                 [--authorized-keys FILE] [--create-on-push] [--detach]
podnet git init NAME [--root DIR]
podnet git urls [--root DIR]      # clone URLs and the host key fingerprint
```

### 5.7 Modules

`src/git/`: `cgi.rs` (generic CGI runner and head parser), `http.rs`
(router, auth, service checks), `ssh.rs` (russh server), `repo.rs` (path
mapping, init, export check), `cli.rs`. Auth shares `src/files/auth.rs`.

### 5.8 Tests

* Skip with a clear line when `git` is not on PATH (as `need_loopback!()`).
* Loopback HTTP (`need_loopback!()`): clone, fetch with protocol v2, push
  with creds; anonymous push 401; wrong password 401; `/../` and
  `/.git/config` refused; a push of 8 MiB with `http.postBuffer=1024`
  (chunked body); an upload-pack request over 1 KiB (gzip body).
* SSH: the russh client in the tree runs `exec git-upload-pack` against the
  server over a unix socket and compares the ref advertisement with `git
  upload-pack --advertise-refs`; unknown command refused; receive-pack with a
  key not in `authorized_keys` refused.
* `live.yml`: `podnet git serve` through a quick tunnel: `git clone` and
  `git push` over HTTPS (creds), anonymous push refused; through `relay node`
  + `ssh -o ProxyCommand='podnet relay connect NAME'` (as the existing step
  "SSH through the reverse relay"): clone and push.

### 5.9 Size

~2 200 lines (CGI 250, HTTP 200, SSH 500, repo 150, CLI 150, tests 700,
plus auth reuse). No new crate. Binary +300-500 KB (the russh server code
becomes linked).

## 6. Shared enablers (do first)

1. `connect --stdio` for `tunnel --forward` (SSH ProxyCommand), as `relay
   connect` already has: ~80 lines. Git over SSH through the tunnel needs it.
2. `relay_reverse::Target::InProcess(handler)`: a node serves an in-process
   handler (files, git SSH, transfer) with no socket file: ~60 lines.
3. One HTTP auth middleware for `--local`, the tunnel and the relay (today
   Basic lives only in the tunnel dispatch, `src/proxy.rs:137`): ~200 lines.
4. The `Network` trait over the five dialers (section 2.4).
5. A resumable relay session (byte offsets, move before 60 MiB / 11 h 30 min,
   as podssh T-155 and `podssh cp`): transfer and git-over-relay need it.
6. A ustar writer/reader (~250 lines) for `serve --tar` and transfer.

## 7. Constraint flags

| Item | Static musl | No root | Flag |
| --- | --- | --- | --- |
| Router L4 (doors, groups, `-L`) | yes | yes | Binding `0.0.0.0` for LAN clients can be refused: use unix doors |
| Router L3 for programs (pod netns/netns-raw) | yes | needs user namespaces; seccomp fallback | Existing limits (field report items 1-2) |
| Kernel multi-WAN (ECMP, nft) | yes | no: CAP_NET_ADMIN, `ip`, `nft` | Keep optional (`warp tun`, mwan export) |
| Tailscale network | yes | yes | Needs an external `tailscaled`; embedding tailscale-rs (podssh `ts` feature) needs C + cmake (aws-lc-sys) |
| vnet shims | n/a | yes | Need a C compiler at run time; no static programs (existing) |
| File server | yes | yes | none |
| File transfer | yes | yes | Third-party mailbox/transit servers by default (privacy); SPAKE2 crate choice |
| Git HTTP (design A) | yes | yes | Runtime `git` (2.19 or later, to confirm); quick tunnel 100 MB push limit |
| Git native (gix) | yes | yes | Heavy, incomplete server side |
| git2 / libgit2 | C build (zig cc) | yes | No server side; bundled C code is GPL-2.0 with a linking exception |
| SSH RSA keys | yes | yes | `rsa` crate advisory fails `cargo deny` (ignore list empty) |

## 8. Open questions for the owner

1. Git: accept the `git` program as a run-time requirement of `podnet git
   serve` (design A), in place of a native server?
2. SSH: allow RSA client keys (russh `rsa` + an advisory ignore in
   `deny.toml`), or ed25519/ECDSA only?
3. Transfer: wire compatible with magic-wormhole/podssh (SecretBox, wormhole
   phases), or a podnet-only protocol? Use the public magic-wormhole and
   Least Authority servers by default, or only a mailbox that the relay
   operator adds?
4. SPAKE2: `spake2 0.4` (duplicate curve crates), `0.5.0-pre.0`
   (prerelease), or own code?
5. Router live test: register a second WARP device in each live run (ruling
   2026-11-04 "do not register WARP devices when it is not necessary")?
6. Resumable relay layer: port podssh's into podnet, or share one crate
   between podnet and podssh?
7. Router config file: YAML through `src/yaml.rs`, or JSON?
