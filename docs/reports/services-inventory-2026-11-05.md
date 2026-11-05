# Inventory: hardcoded and measured services of other parties in podnet

The state of podnet at 66c9512 (2026-11-05). The input of the move to `pod-services` of PodUtils/podcrates (`docs/decisions.md`, Services crate). Line numbers can be approximate. Paths are relative to the repository root.
"Source" says where the value comes from. "Read by" lists the code that uses the constant.
Test-only values (tests, fuzz seeds, doc comments) are listed in one line at the end of each table or in "Stays".

## 1. Lists of hosts

### 1.1 Relay (ajam.dev) and relay-like hosts

| File:lines | Holds | Source | Read by |
|---|---|---|---|
| src/ws_relay.rs:39 `DEFAULT_RELAY` | `https://tcp.ssh.relay.ajam.dev` (default of `--relay`, `PODNET_RELAY`) | unknown (no URL in comment) | src/main.rs:398, 724 (clap default); ws_relay.rs:130, 252, 310 |
| src/relay_pool.rs:25 `DEFAULT_HOST` | `tcp.ssh.relay.ajam.dev` | unknown | relay_pool.rs (same host as above, duplicated) |
| src/relay_pool.rs:31-38 `SEED` | 6 pool hosts: tcp-us-east-1, tcp-eu-west-3, tcp-ap-southeast-1, tcp-azure-westeurope, tcp-us-central1, tcp-ap-south-1 `.ssh.relay.ajam.dev` | "seed of podssh"; measurement 2026-11-04 (`/trace?target=198.41.192.167:7844`, 37 hosts, road `vpc`) in comment | relay_pool.rs:114 (`alternates_of`), reached from ws_relay.rs:256 |
| src/relay_pool.rs:4, 47, 82; src/ws_relay.rs:387-414 | Path `/relays.json` of the relay (pool list), read after a mint, cached in `relay-pool-HOST.json` | relay contract (podssh) | ws_relay.rs:401 (`GET {relay}/relays.json`), `relay_pool::parse_pool`, `store_pool`, `load_pool` |
| src/relay_pool.rs:54-80 `same_deployment` | Rule: a token goes only to hosts under the parent domain of the primary host | design in comment | ws_relay.rs:238, 257 |
| src/relay.rs:41 `DEFAULT_RELAY` | `free.pinggy.io:443` (SSH relay of Pinggy) | unknown | src/relay.rs:61 (`RelayConfig::default`); src/transport/ssh.rs:53 (second copy of the literal) |
| src/relay.rs:404 | Match on `dashboard.pinggy.io` in the relay banner (detects the upgrade text) | measured banner (test text at relay.rs:567-569) | relay.rs:404 |
| examples/edge_probe.rs:56 | `free.pinggy.io:443` default of the example | doc comment line 9 (pinggy result) | the example only |

Tests that repeat relay hosts (stay with the code): src/relay_pool.rs:284-369, src/ws_relay.rs:783-987, tests/relay_reverse.rs:34 (comment), src/manual/facts.rs:113 (text of the default).

### 1.2 DoH resolvers and IP pins

| File:lines | Holds | Source | Read by |
|---|---|---|---|
| src/resolve.rs:46-79 `DOH_SERVERS` | 8 servers by IP: Cloudflare `https://1.1.1.1/dns-query`, `1.0.0.1`, `[2606:4700:4700::1111]`, `[2606:4700:4700::1001]`; Google `https://8.8.8.8/resolve`, `8.8.4.4`, `[2001:4860:4860::8888]`, `[2001:4860:4860::8844]` | none in code; chain described in resolve.rs:11-18 (module comment) | resolve.rs:137 `doh_servers()`; `by_family` (resolve.rs:~109); tests resolve.rs:460-527 |
| src/resolve.rs:123-132 `DOH_SERVERS_BY_NAME` | `https://cloudflare-dns.com/dns-query`, `https://dns.google/resolve`; used only through a proxy | comment lines 120-122 (some proxies refuse CONNECT to an IP) | resolve.rs:138-148 |
| src/resolve.rs:33 `STEP_TIMEOUT` | 5 s limit for each DoH server | none | resolve.rs |
| src/resolve.rs `PINS_VARIABLE` (line 33 area) | `PODNET_RESOLVE` / `--resolve HOST=IP` user pins (not a list of hosts; mechanism) | n/a | resolve.rs |
| src/edge_discovery.rs:159-215 `discover_doh`, `query` | Asks the DoH servers for the SRV and A/AAAA of the edge | n/a | edge_discovery.rs:94 `discover` |
| src/warp/proxy.rs:1493-1510 (tests only) | Resolver parse examples `tls://1.1.1.1#cloudflare-dns.com`, `9.9.9.9` | test fixture | tests |
| src/main.rs:5801 | `nameserver: 1.1.1.1` for `warp tun` | unknown | main.rs (`warp tun`) |
| src/warp/route.rs:12, 541 (comments), 654-672 (tests) | Fallback resolv.conf `1.1.1.1`, `1.0.0.1` for the warp route | comment only | warp/route.rs (code that writes resolv.conf; value is in the function near line 541) |
| src/main.rs:4023, 4206 (help text) and src/manual/facts.rs:228 | `--resolver` default `1.1.1.1:53` named in help text | text | docs |
| src/agent.rs:317, 504 | `1.1.1.1:53` direct UDP DNS probe of the host | none | agent.rs `udp_dns` (see 2) |
| src/warp/proxy.rs:7, 1121 `CHECK_NAME` | `cloudflare.com` A query through the tunnel; DNS over UDP to 1.1.1.1 | none | warp/proxy.rs:1131 `check_data_path` |

### 1.3 Cloudflare tunnel edge (discovery, SNI, addresses)

| File:lines | Holds | Source | Read by |
|---|---|---|---|
| src/edge_discovery.rs:30 `EDGE_SRV` and src/cloudflare/mod.rs:61 `EDGE_SRV` | `_v2-origintunneld._tcp.argotunnel.com` (two copies) | "as cloudflared resolves it" (comment) | edge_discovery.rs:130, 160; cloudflare/mod.rs |
| src/edge_discovery.rs:37-42 `STATIC_EDGE_IPS` | `198.41.192.167`, `198.41.192.227`, `198.41.200.13`, `198.41.200.53` (last-resort anycast) | "Cloudflare's published edge anycast addresses" (no URL) | edge_discovery.rs:233 `static_edges` |
| src/edge_discovery.rs:45-48 `FIXED_TARGETS` | `region1.v2.argotunnel.com:7844`, `region2.v2.argotunnel.com:7844` | comment lines 44, 79 | edge_discovery.rs:81, test 287 |
| src/edge_discovery.rs:62-64 | Check that SRV targets end in `.argotunnel.com` (shape rule) | design | `checked_targets` |
| src/tunnel.rs:602 `EDGE_REGION_NAME` | `region1.v2.argotunnel.com` (proxy choice, NO_PROXY) | none | tunnel.rs:202; preflight.rs:214; doctor.rs:132, 1048 |
| src/cloudflare/mod.rs:49, 52 `QUIC_SNI`, `H2_SNI`; mod.rs:46 `QUIC_ALPN` | `quic.cftunnel.com`, `h2.cftunnel.com`, ALPN `argotunnel` | from cloudflared, comment mod.rs:9-13, quic.rs:11 | cloudflare/quic.rs:102; cloudflare/http2.rs:18, 249 (`H2_SNI`) |
| src/cloudflare/cf-edge-roots.pem | Cloudflare edge roots (see 5) | cloudflared `tlsconfig/cloudflare_ca.go` | cloudflare/mod.rs:70 `CF_EDGE_ROOTS_PEM`; trust.rs |
| src/trust.rs:32 `EDGE_ROOTS_FIRST_END` | `2029-08-15` first expiry of an edge root | measured from the PEM | trust.rs (glue over pod-tls, see "moved") |
| src/udp.rs:33 `PROBE_TARGET` | `198.41.192.167:7844` (UDP probe, needs no DNS) | none | udp.rs:118 `probe_target` (env `PODNET_EDGE` overrides); doctor.rs:116 |
| src/main.rs:5161 | Default `warp probe` targets `1.1.1.1:443`, `198.41.192.27:7844` | none | `WarpCommand::Probe` |
| src/main.rs:6821-6831 (tests) | Door parse examples `162.159.198.1` | test | tests |
| examples/edge_probe.rs:64 | `region1.v2.argotunnel.com` default | none | example |
| examples/warp_probe.rs:44-47; examples/warp_prove.rs:109, 139, 155 | `198.41.192.27:7844`, `1.1.1.1:443`, `1.1.1.1:53`, `93.184.215.14:80` (example.com A) | none | examples |
| src/cloudflare/mod.rs:298-328, src/egress.rs:1521-1529, src/ws_relay.rs:830, src/fuzzing.rs:133, 288-291 | `198.41.192.x`, `198.41.200.x`, region names in tests/fuzz seeds | tests | tests |

### 1.4 Quick tunnel API (trycloudflare)

| File:lines | Holds | Source | Read by |
|---|---|---|---|
| src/quicktunnel.rs:28 `DEFAULT_QUICK_SERVICE` | `https://api.trycloudflare.com` | comment quicktunnel.rs:5 (cloudflared behaviour) | src/config.rs:296; main.rs:375 (`--service-url` default); quicktunnel.rs:879 |
| src/util/mod.rs:105-125 `validate_quick_hostname` | Allowlist: response hostname must be `*.trycloudflare.com` (one label) | design (hostile API response) | quicktunnel.rs (after the POST) |
| src/doctor.rs:120 | `api.trycloudflare.com:443` doctor target `api` | none | doctor.rs `targets()` |
| src/fetch.rs:426-429 (test), src/hop.rs:191-197 (test), src/bug_report.rs:75 | Host in tests or in redaction (`.trycloudflare.com` regex) | test / redaction | tests; `bug_report::redact` |
| src/quicktunnel.rs:526-762 | Captured real response bodies (`REAL_BODY`) | measured, but data in tests | tests |

### 1.5 WARP (Cloudflare) API, front doors, SNI

| File:lines | Holds | Source | Read by |
|---|---|---|---|
| src/warp/register.rs:24 `API_BASE` | `https://api.cloudflareclient.com` | none | register.rs:40, 74, 403 |
| src/warp/register.rs:30 `API_SECOND` | `https://api.devices.cloudflare.com` (fallback host) | "podssh"; resolved 2026-11-02 (comment); owner ruling 2026-11-04 (live.yml:460) | register.rs:40 `api_bases` |
| src/warp/register.rs:34 `API_VARIABLE` | `PODNET_WARP_API` | n/a | register.rs |
| src/warp/register.rs:~37-43 `API_VERSION`, `CLIENT_VERSION`, `USER_AGENT` | `v0a5641`, `a-6.38.9-5641`, `WARP for Android` (client identity the service accepts; goes stale) | "the service rejects a mismatched pair" (comment) | register.rs:403 and headers |
| src/warp/register.rs:110 `MASQUE_SNI`, `MASQUE_PORT` 443 | `consumer-masque.cloudflareclient.com` | none | warp/session.rs:346, 430, 596; doctor.rs:944 |
| src/warp/l4.rs:16 `L4_SNI` | `consumer-masque-proxy.cloudflareclient.com` (L4 front door) | none | l4.rs:239; main.rs:4355 (clap default) |
| src/doctor.rs:109-112 `MASQUE_ADDRESS`, `MASQUE_ADDRESS_V6` | `162.159.198.2`, `2606:4700:103::2` | measured 2026-11-01 (docs/target-environment.md:27) | doctor.rs:144-156, 1208-1220 |
| src/doctor.rs:126, 1210, 1220 | `api.cloudflareclient.com:443` doctor target `warp-api` | none | doctor.rs |
| src/warp/exit.rs:14-21 `TRACE_ADDRESS`, `TRACE_ADDRESS_V6`, `TRACE_NAME` | `1.1.1.1`, `2606:4700:4700::1111`, `one.one.one.one`; `GET /cdn-cgi/trace`; TXT `whoami.cloudflare` (CH) fallback | comment exit.rs:2-3, 92 (issue 184) | exit.rs:87 `trace`, `trace_at`; main.rs:5185 |
| src/warp/mod.rs:979-1018, register.rs:917-929, export.rs:330-345, route.rs:725-738 | `162.159.198.2:443`, `[2606:4700:103::2]:443`, `162.159.192.1`, `engage.cloudflareclient.com:2408` in tests | tests (front door shape from API) | tests |
| src/main.rs:4115, src/warp/mod.rs:203, src/manual/facts.rs:148 | Same names in help text | text | docs |
| src/state.rs:29 `candidates` | Is the state-directory candidate list (not hosts). No door list in code: `warp scan` takes `--candidate` and the device record | n/a | warp scan (see 2) |

### 1.6 GitHub and release hosts read by `podnet update`

| File:lines | Holds | Source | Read by |
|---|---|---|---|
| src/update.rs:27 `REPOSITORY` | `PodUtils/podnet` | repository identity | update.rs:71, 97, 155, 246 |
| src/update.rs:29 `ISSUER` | `https://token.actions.githubusercontent.com` | GitHub OIDC | update.rs (certificate check) |
| src/update.rs:71, 81-82 | `https://github.com/{REPOSITORY}/releases/download/{tag}/{name}`; assets `SHA256SUMS`, `SHA256SUMS.sigstore.json` | release layout | update.rs:530-565 |
| src/update.rs:102 | Identity `https://github.com/{repo}/.github/workflows/release.yml@refs/tags/{tag}` | cosign identity | update.rs:97 `identity_in` |
| src/update.rs:155 | `https://api.github.com/repos/{REPOSITORY}/releases?per_page=30` | none | update.rs `releases()` |
| src/update.rs:237-254 | Fallback `https://github.com/{REPOSITORY}/releases.atom` (issue 166: API answers 403 on a shared address) | issue 166 | update.rs `newest`, `newest_in_atom` |
| src/update.rs:32; src/sigstore-fulcio.pem | Fulcio roots of Sigstore public instance | "trusted root of sigstore/root-signing" (comment update.rs:30-31) | update.rs (`FULCIO_PEM`) |
| src/update.rs:398-400 | OIDs `1.3.6.1.4.1.57264.1.1` (issuer), `.1.8` (Fulcio extension) | Sigstore spec | update.rs |
| src/update.rs:14-16 | Rekor not checked (ruling in CLAUDE.md) | ruling | n/a |
| tests/data/v0.3.0-beta.1.SHA256SUMS(.sigstore.json); update.rs:945-1111 | Fixture signed bundle of an old release | fixture | update.rs tests; also tests/install_script.rs |

### 1.7 Other parties

| File:lines | Holds | Source |
|---|---|---|
| .github/workflows/release.yml:237-260 | `ZIG_VERSION 0.16.0`, `ZIG_SHA256`, `ZIGBUILD_VERSION 0.23.4`; download `https://ziglang.org/download/$ZIG_VERSION/$z.tar.xz` | pinned in workflow |
| .github/workflows/release.yml:496-537, images/podnet/Dockerfile:3 | `ghcr.io/<owner>/podnet:<tag>` push | repo identity |
| .github/workflows/release.yml:408-409; release-proofs.yml:123-133 | Cosign issuer and workflow identity of the repository | repo identity |
| .github/workflows/deny.yml:36 | `https://github.com/EmbarkStudios/cargo-deny/releases/download/$DENY_VERSION/...` | pinned |
| scripts/pull-image.sh:40-52 | Registry fallbacks: `docker.io`, `mirror.gcr.io`, `public.ecr.aws/docker`, `ghcr.io` | none |
| scripts/install.sh:4-5, 84, 334-344, 424-425 | `raw.githubusercontent.com/PodUtils/podnet/main/scripts/install.sh`, `github.com/$repo/releases/download`, `api.github.com/repos/$repo/releases?per_page=30`, `releases.atom`, cosign identity and issuer (shell copy of update.rs logic) | none |
| tools/ts-sshd.sh:25-28, 75-77 | `raw.githubusercontent.com/talaria0101/sandhome/$SANDHOME_COMMIT/...` with pinned commit and SHA-256 | pinned |
| scripts/check-github-numbers.py:44, 103; scripts/agent/watch-issues.sh:22; scripts/agent/watch-runs.sh:14; tools/check-upstream.py:31 | `https://forge.web.pkgforge.dev/github` (mirror of the GitHub API; default), `https://api.github.com` in CI | CLAUDE.md |
| tools/check-upstream.py:32 `REPO` | `cloudflare/cloudflared` (upstream watched) | none |
| src/transport/ssh.rs:53 | `free.pinggy.io:443` literal | see 1.1 |

No STUN, NTP server list, magic-wormhole mailbox or transit server exists in podnet. Time and clock checks use the `Date` header of the quick-tunnel API (src/doctor.rs:507-535). The only NTP packet is a test in live.yml:762-772 (`162.159.200.123:123`, Cloudflare time).

## 2. Code that measures or watches

| File:lines | What it does | Services touched | Data or constants |
|---|---|---|---|
| src/doctor.rs:115-170 `targets`; 478 `run`; 631 `path`; 743 `sample`; 920 `tls`; 1046 `legs`; 507 `clock` | `podnet doctor`: DNS, TCP and TLS samples to the quick-tunnel API, the WARP API, the edge by name and by address, MASQUE (v4 and v6); verdict by road (direct, warp, relay) and a clock check against `Date` | api.trycloudflare.com, api.cloudflareclient.com, region1.v2.argotunnel.com, 198.41.192.167:7844, 162.159.198.2, 2606:4700:103::2 | `MASQUE_ADDRESS*`, `EDGE_REGION_NAME`, `PROBE_TARGET` |
| src/udp.rs:93-170 `probe`, `check_edge_env`, `probe_target`, `packet` | UDP 7844 probe (answered / refused / unknown) | 198.41.192.167:7844 | `PROBE_TARGET`, `PODNET_EDGE` |
| src/edge_discovery.rs:94 `discover`, 122 `discover_system`, 159 `discover_doh`, 231 `static_edges`, 219 `parse_srv`, 52 `checked_targets` | Edge discovery: SRV by the system resolver, then DoH, then a static list | argotunnel.com SRV; DoH servers | `EDGE_SRV`, `FIXED_TARGETS`, `STATIC_EDGE_IPS` |
| src/preflight.rs:7, 29 `edge_row`, 156 `check` | Preflight (`--check`): one SRV lookup of the edge; proxy decision for the edge | argotunnel.com SRV | `EDGE_REGION_NAME` |
| src/resolve.rs:137 `doh_servers` and the chain | Chooses DoH servers by IP family and by proxy | DoH resolvers | `DOH_SERVERS*` |
| src/relay_pool.rs (`parse_pool`, `alternates_of`, `load_pool`, `store_pool`, `same_deployment`) and src/ws_relay.rs:387-414 (background read of `/relays.json`), 349-359 (token mint and cache) | Relay pool read, seed fallback, token cache | `*.ssh.relay.ajam.dev` | `SEED`, `DEFAULT_HOST`, `/relays.json` |
| src/ws_relay.rs `Relay::new`, `from_env`, `single` | Choice of relay and alternates | relay | `DEFAULT_RELAY` |
| src/warp/mod.rs:777-820 `scan` and src/warp/session.rs `probe_door`; src/main.rs:4249, 5071-5082 (`warp scan --candidate`) | Measures each MASQUE front door (TCP, TLS, session times), 8 at once; sorts by time | MASQUE doors from the device record and `--candidate` | `masque_endpoints()` of the device record |
| src/warp/mod.rs:140-155 `door_from` (DOOR_TTL), 831-870 | Chooses a door by age and candidate list (issue 133) | MASQUE doors | door cache |
| src/main.rs:5158-5230 `WarpCommand::Probe` | Probes UDP DNS through the tunnel and each target (default `1.1.1.1:443`, `198.41.192.27:7844`) | 1.1.1.1, edge | defaults in main.rs:5161 |
| src/warp/proxy.rs:1121-1147 `check_data_path` | DNS query for `cloudflare.com` through the tunnel to 1.1.1.1 | 1.1.1.1 | `CHECK_NAME` |
| src/warp/exit.rs:87-230 `trace`, `trace_at`, `trace_v6` | Exit address of a session from `/cdn-cgi/trace` and the `whoami.cloudflare` TXT | 1.1.1.1, one.one.one.one, 2606:4700:4700::1111 | `TRACE_*` |
| src/agent.rs:305-330 `udp_dns`, 504 | Direct UDP DNS check of the host (`warp agent` report) | 1.1.1.1:53 | literal |
| src/vnet/doctor.rs:47-145 `run`, `udp_probe` | Probes of the kernel and the sandbox (bind, unshare). `udp_probe(target)` takes a target from the caller | none hardcoded | n/a |
| src/update.rs:155 `releases`, 237 `newest`, 177 `newest_in_atom`, 193 | Reads the release list and the atom feed | api.github.com, github.com | `REPOSITORY` |
| examples/edge_probe.rs, examples/warp_probe.rs, examples/warp_prove.rs | Manual probes of pinggy, the edge, 1.1.1.1 | see 1.3 | literals |
| src/quicktunnel.rs `request_quick_tunnel` (POST /tunnel) | Provisioning, not a measurement; listed because it reads the service | api.trycloudflare.com | `DEFAULT_QUICK_SERVICE` |

Relay contract watch: no code, script or workflow in podnet. docs/decisions.md:68 (2026-11-05): "The weekly watch of the relay contract belongs to pod-relay (T-134), not to podnet." Listed as: **T-047 (pod-relay), does not move with pod-services** (the TODO entry in the record is T-134 in TODO/later.md:667; T-047 is the `podnet-core` extraction in TODO/crates.md:78).

## 3. Workflows (.github/workflows)

| Workflow / job / step | Service read or measured | Lines |
|---|---|---|
| live.yml, job `live` (nightly cron `47 3 * * *`, line 17) | The whole job runs against live Cloudflare, the relay and WARP | 43-939 |
| step `Edge facts` | runs tools/edge-facts.sh (SRV, A, TLS on 7844) | 74-77 |
| step `podnet doctor` | doctor legs quic, http2, quic+warp; roads direct, warp, relay; clock; `api` DNS | 78-93 |
| steps `Quick tunnel, QUIC (UDP 7844)`, `...HTTP/2 (TCP 7844)`, `...JSON lines`, `...--detach`, `...--auth-user` | trycloudflare quick tunnel; regex `\.trycloudflare\.com$` | 94-170 |
| steps `Quick tunnel with UDP 7844 dropped`, `UDP probe, answered and refused` | edge UDP 7844 | 171-198 |
| step `Quick tunnel through a local CONNECT proxy` | expects `api.trycloudflare.com:443` in the CONNECT log | 199-218 |
| step `Quick tunnel with no system DNS, then with 1.1.1.1 blocked` | blocks 1.1.1.1 and 1.0.0.1 with iptables; expects server `8.8.` | 248-282 |
| step `A wrong --resolve pin fails at the TLS name check` | `api.trycloudflare.com=8.8.8.8` | 283-294 |
| step `podnet update refuses v0.3.0-beta.1 of cfrs` | GitHub releases of PodUtils/podnet | 295-318 |
| step `Autostart with a systemd user unit` | quick-tunnel name wait via scripts/live-wait-name.sh (DoH) | 319-357 |
| steps `Quick tunnel, QUIC through WARP`, `...UDP and TCP 7844 dropped (staggered legs)`, `...through the WebSocket relay (7844 dropped)`, `SSH through the reverse relay` | the relay (default `tcp.ssh.relay.ajam.dev`), WARP | 358-447 |
| step `WARP account and probe` | WARP registration, `warp probe`, expects `udp 1.1.1.1:53` | 448-462 |
| step `WARP API through its second host` | `PODNET_WARP_API=https://api.devices.cloudflare.com` | 463-488 |
| step `WARP probe through the WebSocket relay (MASQUE TCP dropped)` | drops `162.159.198.0/24:443` | 512-526 |
| steps `warp up ...`, `agent up and down`, `WARP run with the netns-raw backend`, `warp tun --default-route ...`, `WARP run`, `WARP proxy` | `https://www.cloudflare.com/cdn-cgi/trace` (`warp=on`), `https://[2606:4700:4700::1111]/cdn-cgi/trace`, `https://ipv6.google.com/`, NTP `162.159.200.123:123` | 527-904 |
| step `Throughput through WARP, 1 to 16 MiB` and the A/B loop | `https://speed.cloudflare.com/__down?bytes=20000000`; download of the beta.6 binary from `github.com/PodUtils/podnet/releases/download/v0.3.0-beta.6/cfrs-x86_64-unknown-linux-musl` (line 835); drops `162.159.198.0/24` (876-882) | 825-904 |
| step `The commands of the second batch` | runs scripts/live-batch2.sh | 905 |
| step `An IPv6-only host` | scripts/v6only/*.sh | 912 |
| job `report` | `gh api repos/$GITHUB_REPOSITORY/actions/workflows/live.yml/runs` (GitHub) | 939-960 |
| upstream.yml, job `upstream` (cron `19 7 * * 1`) | `CHECK_UPSTREAM_API=https://api.github.com` | 9-22 |
| upstream.yml step `The pinned files against cloudflared` | runs tools/check-upstream.py (cloudflare/cloudflared) | 28-29 |
| upstream.yml step `A planted sum fails` | self-test of the check | 30-37 |
| upstream.yml step `The header encoding against the Go code of cloudflared` | runs tools/check-header-oracle.sh (Go source of cloudflared) | 42 |
| release-proofs.yml, job `proofs`, steps `the tag and its commit` (`gh api .../commits/$TAG`, line 48), `the published files` (`gh release download`, 59-64), `the signature of SHA256SUMS` (cosign, issuer and identity regexp, 119-133), `podnet update, on the published x86_64 binary` (146-163) | GitHub releases, cosign and Sigstore public instance | 31-175 |
| release-proofs.yml, job `rebuild` (176) | rebuilds and compares with the published SHA256SUMS | 176-215 |
| record-issues.yml, job `numbers`, step `TODO/github.txt against GitHub` (cron `43 5 * * *`) | `CHECK_GITHUB_API=https://api.github.com` | 9-38 |
| record-issues.yml step `A planted drop fails the check` | self-test | 37 |
| release.yml: steps with Zig download (254-266), cosign and attestation (408-409), `ghcr.io` image push (470-537) | ziglang.org, ghcr.io, GitHub | see 1.7 |
| deny.yml (line 36) | GitHub release download of cargo-deny | see 1.7 |
| ci.yml, publish.yml, fuzz.yml, secrets.yml | `rustup` and `apt-get` installs only, crates.io trusted publishing (publish.yml:3-4). fuzz.yml reads no service. Not services of the pod-services kind | n/a |

## 4. Scripts and tools

| File:lines | Does | Services | Source of values |
|---|---|---|---|
| tools/edge-facts.sh:1-70 | Measures edge facts of docs/protocol.md section 6: SRV, A records of region1 and region2, TLS on 7844 with SNIs `h2.cftunnel.com`, `probe.cftunnel.com`, `region1.v2.argotunnel.com`, no SNI, ALPN, key groups, ports 443, 8443, 80, first bytes; exit 1 when TLS 1.3 with SNI `h2.cftunnel.com` and no ALPN does not verify against the roots | `_v2-origintunneld._tcp.argotunnel.com`, `region[12].v2.argotunnel.com`, `h2.cftunnel.com` | comment lines 1-12 |
| tools/check-upstream.py:1-120 | Compares `cloudflared-pin.txt` entries with cloudflare/cloudflared at the pinned tag and at the newest release (SHA-256 of capnp schemas, roots, source files); pin age at most 9 months (`MAX_AGE_DAYS = 274`); `--plant-sum` self-test | GitHub API via `https://forge.web.pkgforge.dev/github` (default) or `CHECK_UPSTREAM_API`; repo `cloudflare/cloudflared` | docstring |
| tools/check-header-oracle.sh | Header encoding against the Go code of cloudflared (`connection/header.go`); includes the verbatim Go code and `header-oracle.txt` | cloudflared source (Go), CI only | comment line 74 |
| tools/header-oracle.txt | Data for the oracle | n/a | n/a |
| tools/prove-warp.sh:28-40 | Control that the host cannot reach `198.41.192.27`, `198.41.200.13` on 7844, then proves it through WARP | edge IPs | `EDGES` variable (line 28) |
| tools/ts-sshd.sh:25-28, 75-77 | Fetch of `errandsh`, `faketty`, `fakepty.c` from GitHub talaria0101/sandhome at a pinned commit and SHA-256 | raw.githubusercontent.com | pinned in script |
| scripts/live-run.sh:3, 18-19 | Runs a live command and redacts hosts: `[a-z0-9-]+\.trycloudflare\.com` except `api.trycloudflare.com` | trycloudflare name shape | none |
| scripts/live-wait-name.sh:19 | Waits until a quick-tunnel host resolves: system resolver, then DoH `https://1.1.1.1/dns-query`, `https://8.8.8.8/resolve`; adds an `/etc/hosts` line | Cloudflare and Google DoH | comment lines 1-9 (issue 119) |
| scripts/live-batch2.sh:64, 89, 107-109, 161-250, 273 | `warp scan --candidate 162.159.198.1`; `www.cloudflare.com/cdn-cgi/trace`; `speed.cloudflare.com/__up` and `__down?bytes=20000000`; SNI loop `consumer-masque-proxy.cloudflareclient.com`, `consumer-masque.cloudflareclient.com` (216); `quic-vn.py 162.159.198.2 443` | WARP front doors, Cloudflare speed test | none |
| scripts/quic-vn.py:1-60 | Sends a QUIC Initial with a reserved version and prints the versions the endpoint lists (issue 157) | any UDP host; used with `162.159.198.2:443` | RFC 9000 and 9369 |
| scripts/live-share.sh:22; scripts/live-ws-url.sh:19-52; scripts/live-throughput.sh:39-61 | Redaction of `*.trycloudflare.com` in logs; run live tunnels | trycloudflare | none |
| scripts/box/probe.py:19-85 | Probes of the test box (direct TCP to `1.1.1.1:443`, UDP DNS to `1.1.1.1:53`, `api.trycloudflare.com` name and 443, `region1.v2.argotunnel.com:7844`, `1.1.1.1:443` and `162.159.198.2:443` through the proxy) | Cloudflare | scripts/box/report.txt (expected facts) |
| scripts/box/proxy.py:9 | Test proxy; door `162.159.198.2:443` in text | n/a | comment |
| scripts/test_in_box.sh:80 | `proxy "$port" --allow 162.159.198.2:443` | MASQUE door | none |
| scripts/v6only/up.sh:49 | resolv.conf `1.1.1.1`, `8.8.8.8` inside the netns | public resolvers | none |
| scripts/v6only/acceptance.sh:22, 67 | IPv4 connect to `1.1.1.1:443` must fail; `https://1.1.1.1/cdn-cgi/trace` | Cloudflare | none |
| scripts/install.sh (see 1.7) | Release fetch, atom fallback, cosign check | GitHub, Sigstore | none |
| scripts/check-github-numbers.py:16-44, 103 | Checks `TODO/github.txt` against GitHub issue numbers | GitHub API via forge.web.pkgforge.dev | CLAUDE.md |
| scripts/agent/watch-issues.sh:9-22; scripts/agent/watch-runs.sh:14-29; scripts/agent/new-issues.py; scripts/agent/runs.py | Poll issues and workflow runs of PodUtils/podnet | forge.web.pkgforge.dev/github | CLAUDE.md |
| scripts/pull-image.sh:40-52 | Image pull with registry fallbacks | docker.io, mirror.gcr.io, public.ecr.aws, ghcr.io | none |
| scripts/socks5-udp-dns.py, scripts/connect-proxy.py, scripts/origin-sink.py, scripts/ws-client.py, scripts/restricted-host.sh, scripts/soak.sh | Local fixtures; no remote host (only example names) | none | n/a |

## 5. Data files

| File | Holds | Source | Read by |
|---|---|---|---|
| src/cloudflare/cf-edge-roots.pem | Cloudflare edge roots (Origin SSL ECC CA, valid to 2029-08-15) | cloudflared `tlsconfig/cloudflare_ca.go` (cloudflared-pin.txt:11, sha256) | `include_bytes!` in src/cloudflare/mod.rs:70; tools/edge-facts.sh:15 (`-CAfile`); tools/check-upstream.py (compares certificates); src/trust.rs:15, 32 |
| src/cloudflare/cloudflared-pin.txt | Pin of cloudflared 2026.10.7 (commit 872b241f, released 2026-10-30), `copy`, `roots`, `source` lines with SHA-256 | cloudflared repository | tools/check-upstream.py; src/cloudflare/mod.rs:342 (test via `include_str!`), SPEAKS at mod.rs:67-68; tools/check-header-oracle.sh:74 (comment) |
| src/cloudflare/schemas/*.capnp | `tunnelrpc.capnp`, `quic_metadata_protocol.capnp` copies | cloudflared (pin lines 8-9) | build of src/cloudflare/capnp.rs, rpc.rs, schema.rs |
| src/sigstore-fulcio.pem | Fulcio intermediate and root of Sigstore public instance | sigstore/root-signing trusted root | src/update.rs:32 `FULCIO_PEM` |
| tests/data/v0.3.0-beta.1.SHA256SUMS and `.sigstore.json` | Fixture of a real signed release (identity of the old repository `Azathothas/cfrs`) | a real release | src/update.rs:945-946; tests/install_script.rs |
| tools/header-oracle.txt | Oracle vectors | cloudflared Go code | tools/check-header-oracle.sh |
| scripts/box/report.txt | Expected facts of the test box (sandbox) | docs/target-environment.md, 2026-11-01 | scripts/box/probe.py consumers, test_in_box.sh |
| .github/secrets-allow.txt, scripts/size-allow.txt | Allowlists of own tools (not services) | n/a | secrets.yml, check-size.py |
| No `relays.json` file exists in the repository. The pool cache is written at runtime as `relay-pool-HOST.json` in the state directory (src/relay_pool.rs) | | | |

## 6. Documents that list hosts (short)

- README.md:8 (trycloudflare), :18 (DoH 1.1.1.1, 8.8.8.8, static edge list), :142 (GITHUB_TOKEN to api.github.com only), :429 (relay default `https://tcp.ssh.relay.ajam.dev`).
- SECURITY.md:41 (quick tunnel hostnames are public), :53 (DoH Cloudflare 1.1.1.1, 1.0.0.1; Google 8.8.8.8, 8.8.4.4), :61 (relay `tcp.ssh.relay.ajam.dev` and its pool).
- docs/target-environment.md:23-27 (measured: TLS to `api.trycloudflare.com`, CONNECT to `1.1.1.1:443`, to edge `198.41.200.x:7844`, doctor 2026-11-01 incl. MASQUE).
- docs/protocol.md:13-37 (quick tunnel POST, SRV `_v2-origintunneld._tcp.argotunnel.com`, regions, port 7844) and section 6 (edge facts from tools/edge-facts.sh).
- docs/decisions.md:68 (relay contract watch), docs/maintenance.md (workflows and watch tools).
- crates/podnet-netns/README.md:162 (`198.18.0.0/15` pool: private range).
- src/manual/facts.rs:33, 113, 148, 228, 438, 470 and src/manual/model.rs:81: man page text with the same hosts. These must change with the constants.

## 7. May stay in podnet

| Item | Reason |
|---|---|
| src/update.rs:27 `REPOSITORY` `PodUtils/podnet`, :29 `ISSUER`, :71-102, :155, :246; tests/data/*.sigstore.json; live.yml step `podnet update refuses ...`; release-proofs.yml signature and update steps; scripts/install.sh cosign identity | The repository's own GitHub identity for update signature checks. Stays with the `podnet update` code. (The Fulcio roots in src/sigstore-fulcio.pem are Sigstore's: could move as a service fact, but they are a trust anchor of podnet's update.) |
| src/ws_relay.rs `Relay` logic and `relay_reverse.rs`, tests/relay_reverse.rs | podnet's own relay client. The host list (DEFAULT_RELAY, SEED, DEFAULT_HOST) can move; the pool cache and token logic are code of the client (planned for pod-relay) |
| src/relay.rs:41 and src/transport/ssh.rs:53 (pinggy default) | Transport of `--transport ssh`: a user-chosen relay; default can move as data but the SSH client stays |
| src/cloudflare/*.rs protocol constants (SNI, ALPN, `SPEAKS`), schemas, cf-edge-roots.pem, cloudflared-pin.txt | Protocol of the Cloudflare adapter (moves to `pod-cloudflare`, not `pod-services`, per CLAUDE.md). Only the watch tools tools/check-upstream.py and tools/edge-facts.sh relate to measuring |
| src/util/mod.rs:105-125 `validate_quick_hostname` | Security rule of the Cloudflare adapter, not a host list |
| src/doctor.rs, src/udp.rs, src/preflight.rs, src/vnet/doctor.rs (functions) | Podnet commands. They take targets from the list; the targets can come from pod-services |
| scripts/check-github-numbers.py, scripts/agent/*, record-issues.yml, TODO/github.txt | Repository management of podnet itself (PodUtils/podnet issues) |
| scripts/box/*, scripts/test_in_box.sh, scripts/restricted-host.sh, scripts/socks5-udp-dns.py, scripts/connect-proxy.py, scripts/origin-sink.py, scripts/ws-client.py | Test fixtures of podnet; loopback only (box facts name Cloudflare addresses but test podnet's behaviour) |
| tools/prove-warp.sh, examples/warp_prove.rs | Proofs of podnet's WARP stack; edge IPs are test inputs |
| Build and CI hosts: ziglang.org, ghcr.io, EmbarkStudios/cargo-deny, rustup, apt, mirror.gcr.io | Build infrastructure of podnet, not services podnet talks to |
| tools/ts-sshd.sh (talaria0101/sandhome) | Test helper with pinned commit and hash |
| Test fixtures with `x.trycloudflare.com`, `example.com`, `stun.example`, `198.18.0.0/15`, `1.2.3.4`, `93.184.x`, `10.66.0.x`, `172.16.0.2` | Fixtures and private ranges. The edge IPs in test fixtures (src/cloudflare/mod.rs:298-328, egress.rs:1521-1529) need no change |
| Loopback (127.0.0.1, ::1, localhost) in tests/ and scripts | Loopback only |

## 8. Files already moved to podcrates

- src/trust.rs (166 lines): glue over `pod-tls` (`pod_tls::Context`, `SYSTEM_BUNDLES`, `ROOTS_VERSION`, `clock_hint`). It still holds `EDGE_ROOTS_FIRST_END = "2029-08-15"` (line 32), which is a fact about `cf-edge-roots.pem` and moves with that file.
- src/tls_fragment.rs: gone (not in src/). No reference found in the scan.
- No workspace crate for hosts exists yet: crates/ has `podnet-netns` and `podnet-todo` only. `podnet-netns` has no service host (only `1.1.1.1` and `1.2.3.4` in tests: crates/podnet-netns/tests/raw.rs:38-75, src/upstream.rs, src/socks.rs:565).

## 9. Duplicates and drift risks (for the move)

- `tcp.ssh.relay.ajam.dev` appears in ws_relay.rs:39 and relay_pool.rs:25 (two constants, one fact).
- `EDGE_SRV` appears in edge_discovery.rs:30 and cloudflare/mod.rs:61.
- `region1.v2.argotunnel.com` appears in tunnel.rs:602, edge_discovery.rs:46, examples/edge_probe.rs:64, tools/edge-facts.sh, scripts/box/probe.py:84.
- Edge IPs differ: `198.41.192.167` (udp.rs:33, STATIC_EDGE_IPS), `198.41.192.27` (main.rs:5161, examples, tools/prove-warp.sh, tools/... `warp_probe`), `198.41.200.13` (STATIC_EDGE_IPS, prove-warp.sh). No source comment says which is current.
- `162.159.198.2` (MASQUE front door) appears in doctor.rs:109, scripts/live-batch2.sh:273, scripts/box/probe.py:85, scripts/test_in_box.sh:80, live.yml:516 and 876 (as /24).
- `1.1.1.1` literal in at least 12 places (resolve.rs, agent.rs, warp/exit.rs, warp/proxy.rs, main.rs:5161, 5801, probes in scripts, live.yml).
- `free.pinggy.io:443` appears in relay.rs:41, transport/ssh.rs:53, examples/edge_probe.rs:56.
- The shell copy of the update logic (scripts/install.sh) repeats the GitHub URLs of update.rs.
