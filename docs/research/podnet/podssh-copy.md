# podssh to podnet: what podnet can copy, and how

Sources (read only):

* podssh: `/workspace/azathothas/podssh` at `427f890` ("The record: the
  twelfth round of drafts"), a shallow clone of 1 commit, read on
  2026-11-05. No fetch was necessary.
* cfrs: `/workspace/cfrs` at `3bed023`.
* The study reports `podssh.md`, `architecture.md`, `capabilities.md`,
  `mwan-field.md`, `rename.md`, `vn.md` in this directory.

Owner rule (confirmed): "no regression" means no loss of a feature or a
capability of the code. Compatibility for existing users is not required.

Trials (scratch copies only; nothing in either repository changed):

* `scratchpad/todo-trial/`: `crates/podssh-todo` as is, in an empty
  workspace (edition 2021, MSRV 1.89), with cargo 1.97.0.
  `cargo clippy --all-targets -- -D warnings`: clean.
  `cargo test --no-fail-fast`: 108 of 112 pass. The 4 failures read
  podssh's own repository (`tests/github.rs` 2, `tests/interop.rs` 1,
  `tests/repository.rs` 1).
* `scratchpad/layer-trial/`: `crates/podssh-relay/src/session/` (the
  resumable layer) as a standalone crate, with 3 shims: `text.rs` (97 lines)
  and `wake.rs` (195) copied from `podssh-ws`, and `open::backoff`
  (10 lines). Dependencies: tokio, sha2 0.11, hmac 0.13, hkdf 0.13,
  x25519-dalek 3, rand 0.10, zeroize, libc. `cargo clippy -- -D warnings`:
  clean. 18 of the 21 `tests/session_*.rs` files copied with
  `s/podssh_relay::/layer_trial::/`: 135 tests pass, 0 fail. Against the cfrs
  lock, the only new crate is `x25519-dalek 3.0.0` (BSD-3-Clause; its
  `curve25519-dalek 5.0.0` is in the cfrs lock).
* `scratchpad/podssh-fmt/`: rustfmt with the cfrs default width (100) over
  `session`, `e2e`, `code`, `transit`, `identity`, `udp` and
  `podssh-todo/src`: 18,339 lines become 21,516 (+17 %). podssh uses
  `max_width = 120` (`rustfmt.toml`). 7 files pass 500 lines; none passes
  800.

---

## 0. Verdict

* podssh has 260,033 lines of Rust in `crates/*/src` (1,283 files) and
  109,407 lines of tests, plus 185,153 lines in `vendor/`, 32,537 in
  `scripts/`, 20,429 in `docs/`, 76,837 in `TODO/`.
* Most of podssh is an SSH client and its UX (`podssh-cli`, `podssh-ssh`,
  `podssh-terminal`, `podssh-core`): podnet needs none of it.
* Where podssh and cfrs overlap (WARP MASQUE, the quick tunnel, the egress
  proxy, DoH, the TLS crypto, update, detach, doctor, manual), the cfrs code
  is the superset or the project rule. Keep cfrs in each overlap.
* podnet can copy now, with small adaptation, about 27,000 lines (about 7 %
  of podssh's crate code, src and tests):
  1. `crates/podssh-todo` (the TODO tool), as `crates/podnet-todo`.
  2. The resumable relay layer (`podssh-relay/src/session/`, T-155 resume
     included), the end-to-end channel (`e2e/` core) and the key identity
     (`identity/`), UDP in a stream (`udp/`): into `podnet-relay`.
  3. The rendezvous parts of file transfer: the magic-wormhole mailbox
     client, SPAKE2 and SecretBox phases, the code words (`code/`, without
     the pairing exchange) and the transit carrier (`transit/`).
  4. The WARP stand-in edge and API stand-in (test harness) from
     `podssh-warp`, so that cfrs WARP commands get loopback tests.
  5. Tooling: `scripts/check-github-numbers.py` + `record-issues.yml`,
     check 1 (file size) of `scripts/check-repo.py`, `scripts/fetch-zig.sh`
     + `scripts/zig-mirrors.txt`, the headscale harness pattern, the relay
     contract watch, `scripts/wormhole-peer.py`.
* Later, behind cargo features and after the traits (architecture step F):
  the extra egress roads of `podssh-ws` (an `https://` proxy, VLESS,
  Shadowsocks, wstunnel, Wisp), the DERP carrier, the ACME client, the
  in-process Tailscale (`podssh-ts` + the vendored fork), iroh, and the relay
  role (a self-hosted relay and mailbox). Each needs an owner decision.
* No podssh code exists for: the file server, git hosting (only a russh
  test server), the router (multi-WAN), the seccomp/netns fixes, a tar
  writer, the layer check, the WireGuard responder.
* Sharing: copy and own the code, with a pin file and a weekly watch of the
  podssh files (the pattern of `tools/check-upstream.py` and
  `src/cloudflare/cloudflared-pin.txt`). Do not add a git dependency on
  podssh now (section 4).

---

## 1. Inventory of podssh

### 1.1 Crates

Lines: `crates/X/src` and `crates/X/tests`, `wc -l`. Tests: count of
`#[test]` and `#[tokio::test]` in `src` (unit) and `tests` (integration).
"Lock closure" counts the packages that `Cargo.lock` reaches from the crate,
dev-dependencies included (an upper bound).

| Crate | src (files) | tests | unit / integ. (ignored) | Internal deps | External deps (notable) | C / Go | What it does | Maturity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `podssh-cli` | 117,800 (588) | 55,257 | 975 / 1,095 (65) | all crates (ts, iroh, warp, tor optional) | clap 4.6, rustls, aws-lc-rs 1.16, rcgen, x509-parser, roxmltree, vt100 | C (aws-lc-sys via aws-lc-rs) | The `podssh` binary: arguments, manual (`man/` 7,385), `ssh/` 15,295, `cp/` 10,074, `doctor/` 8,302, `pipe/` 5,848, `net/` (own mesh) 3,969, `chat/`, `detach/`, `mcp/`, `update/`, `relay_serve/`, `acme/` 1,372, `node_*`, `ts/` | Shipped (release features `iroh,warp`) |
| `podssh-ssh` | 35,021 (165) | 3,237 | 351 / 76 (1) | ws | russh 0.65 (vendored, 4 patches; `aws-lc-rs`, `rsa`, `flate2`), russh-sftp 3, ssh-key (vendored, 1 patch), pkcs5/pkcs8, des, cbc, chrono | C (aws-lc) | SSH client: `known_hosts`, auth, agent, keygen, SFTP client, FIDO keys, terminal | Shipped |
| `podssh-relay` | 58,682 (275) | 27,309 | 512 / 539 (27) | ws; warp (optional) | snow 0.10, x25519-dalek 3, ed25519-dalek 2, hkdf/hmac/sha2; optional: spake2 0.4, crypto_secretbox 0.1, crypto_box 0.9, h2, noq 1.4 | none (gate builds it with `CC=/nonexistent`) | Relay client (hosts, pool, rank, tokens, failover, cleartext/h2/HTTP/QUIC roads), reverse road and pairs, `session/` (resumable layer) 7,468, `e2e/` (Noise XX) 3,376, `identity/` 694, `grant/`, `udp/` 352, `quick/` (Cloudflare quick tunnel) 6,180, `derp/` 3,543, `transit/` 1,013, `piping/` 2,439, `opentunnel/` 2,563, `code/` 1,824, `serve/` (relay role) 11,793, `blocking/` (facade for podbox) | Shipped with features `pair quick quic derp serve piping opentunnel grant code`; `blocking`, `plain-ws`, `warp-stand-in` are test or embedder features |
| `podssh-ws` | 24,776 (127) | 12,089 | 229 / 312 (11) | none | rustls 0.23 with no provider; own pure-Rust provider (`crypto/` 2,448: aes-gcm 0.11, chacha20poly1305 0.11, p256, p384, rsa 0.9, x25519 3, ed25519 2); h2, md5, sha1 | none | TCP and proxy dial, TLS, WebSocket client and server, DoH (`resolve/` 2,215), ECH, MPTCP, STUN; roads: `via` (HTTPS proxy, 811), `vless` 1,527, `wstunnel` 696, `wisp` 1,331, `shadowsocks` 1,183, `forwarder` 816, `cloudflare` (cloudflared access client, 185), `meek`, `webtunnel`, `eice`, `iap` | Shipped |
| `podssh-warp` | 5,469 (28) | 362 | 71 / 8 | ws | h2, smoltcp 0.14, p256 | none | WARP MASQUE over HTTP/2 only, TCP only: register, pinned TLS, capsules, smoltcp stack, DNS inside, probe, endpoint order; `stand_in.rs` (a fake edge) | Shipped (feature `warp`); MSRV 1.91 |
| `podssh-iroh` | 3,640 (22) | 1,727 | 30 / 33 | relay (derp), ws | iroh 1.4 (`tls-aws-lc-rs`), iroh-relay (vendored, SOCKS5 patch), noq-proto | C (aws-lc) | The iroh road: QUIC between keys, relays over HTTPS | Shipped (feature `iroh`); MSRV 1.91 |
| `podssh-ts` | 895 (10) | 899 | 0 / 46 | ws | `vendor/tailscale-rs` (path) | C (aws-lc-sys, cmake) | In-process tailnet node: `TsConfig` in, `TsNode` out; `podssh ts`, `ts -W PEER:PORT` | Not in release binaries (feature `ts` off); MSRV 1.92 |
| `podssh-tor` | 938 (6) | 372 | 9 / 8 | ws | arti-client 0.47 (`static-sqlite`) | C (bundled SQLite) | Tor road through Arti | Not shipped (feature `tor`); MSRV 1.92 |
| `podssh-core` | 5,005 (25) | 3,583 | 1 / 141 | none | sha2, hex | none | Sans-IO IRC client and chat | Shipped (`podssh chat`) |
| `podssh-terminal` | 3,691 (18) | 2,830 | 73 / 103 | none | unicode-width | none | Line discipline (not used, T-111), terminal grammar | Shipped (grammar) |
| `podssh-probe` | 504 (3) | 326 | 0 / 18 | none | toml, regex, serde, sha2 | none | Relay contract facts (`facts/relay-facts.toml`) and their checks | Linked by the CLI |
| `podssh-todo` | 3,612 (16) | 1,416 | 28 / 85 | none | none (std; calls `git`) | none | Checker and writer of `TODO/` | Dev tool |

Totals: src 260,033 lines, tests 109,407 lines. Lock: 864 packages.
Workspace: edition 2021, MSRV 1.89, `publish = false`, licence 0BSD,
`rustfmt.toml` `max_width = 120`. Release profile: `opt-level = "z"`, LTO,
`panic = "abort"`. The workspace rule: library crates build with
`CC=/nonexistent` (`scripts/gate.sh`).

Platforms: podssh ships Linux musl for 4 targets only (x86_64, aarch64,
armv7, riscv64gc; `deny.toml` `[graph] targets`), plus macOS and Windows.
podnet ships 8 Linux targets. No podssh crate that needs C was ever built
for i686, arm (v6), loongarch64 or powerpc64le.

### 1.2 Top-level tooling

| Path | Size | Contents | Already in cfrs? |
| --- | --- | --- | --- |
| `scripts/` | 142 entries, 794 files with `plants/` (646), 32,537 lines | `gate.sh` (473: the CI gate, `CC=/nonexistent` builds, MSRV steps, plants), `check-repo.py` (455: 11 repository checks, floors, `--plant-empty`), `check-scripts.py`, `check-github-numbers.py` (101), `check-upstream.py` (cloudflared pin), `check-vendored.py` (146), `check-vendored-advisories.py` (257), `check-release-tools.py` (74), `check-relay-spec.py` (498) + `relay_watch.py` (155) + `relay-spec-agree.py`, `fetch-zig.sh` (47) + `zig-mirrors.txt`, `release-check*.sh` (T-251, about 1,280 lines), `release-short.sh` (115), `ts-headscale.sh` (434) + `ts-headscale-lib.sh` (233), `wormhole-peer.py` (62), about 60 `interop-*.sh` (OpenSSH, Dropbear, terminals), `fake-*.py` stand-ins, `test_in_box.sh` + `box/` | cfrs has `check-workflows.py` (action pins, permissions), `release-short.sh`, `test_in_box.sh` + `box/`, `binfmt.sh`, `pull-image.sh`, `secrets-report.py`, `tools/check-upstream.py`, `scripts/agent/*` |
| `.github/workflows/` | 42 files, 4,961 lines | `build.yml` (gate, 445), `release.yml` (622), `release-proofs.yml`, `update-live.yml`, `deny.yml`, `secrets.yml`, `fuzz.yml`, `upstream.yml`, `plants.yml`, `record-issues.yml` (44), `relay-watch.yml` (132), `ts-headscale.yml` (49), `pair-code.yml` (49), `transit-live.yml`, `warp-live.yml`, about 25 more live and interop jobs | cfrs has `ci.yml`, `release.yml`, `release-proofs.yml`, `live.yml`, `deny.yml`, `secrets.yml`, `fuzz.yml`, `upstream.yml` |
| `fuzz/` | 23 targets, 4,530 lines | cargo-fuzz, own workspace: capnp, SOCKS5, proxy URL, NO_PROXY, WS frame and upgrade, warp capsule, quick tunnel, relay list and pool, DNS wire, known_hosts, IRC | cfrs has 16 targets of its own code |
| `images/` | 9 Dockerfiles, 42 lines | pinned by digest: `armv7`, `binfmt`, `box`, `box-proxy`, `build`, `derper` (Go image, builds `derper`), `headscale` 0.29.7, `tailscale` v1.104.4, `trufflehog` | cfrs has `armv7`, `binfmt`, `build`, `cfrs`, `trufflehog` |
| `vendor/` | 185,153 lines of Rust | `tailscale-rs` (fork at `f4781c4`, 40 manifests, 70,135 lines, edition 2024, MSRV 1.92, BSD-3-Clause + PATENTS, 29 patches + `LOCAL-PATCHES.md`); `russh` 0.65.0 (34,861, 4 patches); `ssh-key` 0.7.0-rc.11 (14,522, 1 patch); `iroh-relay` (13,740, 1 patch); `README.md` (policy: upstream, commit, "Upstream read", licence, re-vendor steps) | No `vendor/` in cfrs |
| `docs/` | 33 files, 20,429 lines | `cli.md` 5,795, `relay.md` 1,560, `design.md` 1,555, `carriers.md` 1,470 (research of NetBird, Firezone, ZeroTier, ...), `STATUS.md` 1,259 (509 KB), `development.md` 1,065, `reverse.md`, `mesh.md`, `tailscale.md`, `decisions.md`, `ROADMAP.md`, `releases/`, `research/` | cfrs has its own documents |
| `TODO/` | 28 files, 76,837 lines | The record: `INDEX.md`, `PROGRESS.md`, `RULES.md` (173), `issues.md`, `github.txt`, 23 area files; 637 entries | No |
| `AGENTS.md` | 378 lines | Session loop, task-to-documents table, safety, code rules (500-line rule, no `LD_PRELOAD`), change procedure, path map | cfrs has `CLAUDE.md` |
| `cliff.toml`, `about.toml` + `about.hbs`, `deny.toml` | small | git-cliff, cargo-about, cargo-deny (10 targets incl. macOS and Windows; ignores RUSTSEC-2023-0071 (`rsa`) and RUSTSEC-2024-0436 (`paste`); MPL-2.0 exceptions) | cfrs has all three (8 musl targets, `ignore = []`) |
| `.cargo/config.toml` | | `[alias] todo = "run -q -p podssh-todo --"`; `incompatible-rust-versions = "fallback"` | cfrs has the resolver line and `SMOLTCP_IFACE_MAX_ADDR_COUNT = "8"` |

Licence: `LICENSE` is the BSD Zero Clause License, "Copyright (C) 2026
Azathothas". cfrs is 0BSD, same owner. Code from podssh needs no notice.
The vendored third-party trees keep their licences (tailscale-rs:
BSD-3-Clause with PATENTS; a notice line in `THIRD_PARTY_NOTICES.md` and
cargo-about).

---

## 2. podnet needs and the podssh code that covers them

| Need (report) | podssh code | Verdict |
| --- | --- | --- |
| TODO model and tool (podssh.md, CONTEXT) | `crates/podssh-todo`, `TODO/RULES.md`, `scripts/check-github-numbers.py`, `.github/workflows/record-issues.yml`, `scripts/plants/t360-record-row.*` | Copy as is, then adapt constants (2.1) |
| File transfer: short code, PAKE (capabilities 4) | `podssh-relay/src/code/`: `mailbox.rs` 324, `wormhole.rs` 385, `phrase.rs` 170, `words.rs` 123, `mod.rs` 183; `run.rs` 383 and `exchange.rs` 256 are the pairing exchange | Copy and adapt the mailbox, SPAKE2/SecretBox phases and words; reimplement the exchange as a file offer (2.2) |
| File transfer: carriers | `transit/` 1,013 (magic-wormhole transit relay); `piping/`, `opentunnel/`, `derp/` (other carriers) | Copy and adapt `transit/`; the others later |
| File transfer: end-to-end encryption | `e2e/` (Noise XX, snow) | Copy the core with the layer (2.3) |
| File transfer: resume across the 64 MiB relay cap | `session/` (T-151 to T-155, T-262, T-270) | Copy and adapt (2.3) |
| Relay resume T-155 (capabilities enabler 6.5) | `session/beside.rs`, `resume.rs`, `pump.rs` (`Watch`), `record.rs` (`RETIRE` 0x0b), `Settings::move_bytes` 48 MiB, `move_age` 11 h | Copy with the layer (2.3) |
| WebSocket relay client | `relay.rs`, `pool.rs`, `open.rs`, `failover.rs`, `token.rs`, `cache.rs`, `gate.rs`, `rank*.rs`, `cleartext.rs`, `h2_road.rs`, `http_road/`, `quic_road/`, `reverse/`, `pair/` | Keep cfrs `ws_relay.rs`/`relay_pool.rs`/`relay_reverse.rs`; take ideas only (2.4) |
| Other carriers ("bring your own network") | `podssh-ws`: `via`, `vless`, `wstunnel`, `wisp`, `shadowsocks`, `forwarder`, `cloudflare`, `meek`, `webtunnel` | Copy and adapt later, as `Dialer` adapters after step F (2.4) |
| In-process Tailscale (podssh.md 2) | `crates/podssh-ts`, `vendor/tailscale-rs`, `vendor/patches/` | Later, behind a feature, owner decision (2.5) |
| Headscale CI harness | `scripts/ts-headscale.sh`, `ts-headscale-lib.sh`, `ts-headscale.yml`, `images/{headscale,tailscale}` | Copy and adapt to test the cfrs sidecar front door (2.5) |
| iroh, DERP, mesh | `podssh-iroh`, `podssh-relay/src/derp/`, `podssh-cli/src/net/` | Later or skip (2.6) |
| WARP, MASQUE | `podssh-warp` | Keep cfrs; copy the stand-in edge for tests (2.6, 2.11) |
| SSH server for git hosting (capabilities 5.4) | No production server. `podssh-cli/tests/ssh_harness/` (2,054 lines): a russh 0.65 server in tests (exec, pty, direct-tcpip, streamlocal, sftp subsystem, x11) | Reimplement on cfrs russh 0.64; read the harness as an API example (2.7) |
| File server (capabilities 3) | None | Reimplement (capabilities.md plan) |
| Router, multi-WAN (mwan-field) | None (podssh mesh has exits and routes, no weights or health) | Reimplement |
| seccomp/netns fixes, vn ideas | None (podssh rule: no `LD_PRELOAD`, no shims) | Reimplement |
| tar writer (capabilities 6.6) | None | Reimplement |
| File-size check | `scripts/check-repo.py` check 1 (500 lines, `crates/` and `scripts/`, floors) | Copy and adapt (allowlist) (2.8) |
| Layer check | None (crates make the layers) | Reimplement from `study/tools/graph.py` |
| Release tooling | `fetch-zig.sh` + mirrors, `check-release-tools.py`, `release-check*.sh`, `update-live.yml` | Copy `fetch-zig.sh` + mirrors; cfrs has the rest (2.9) |
| Upstream watch | `check-upstream.py`, `check-vendored.py`, `check-vendored-advisories.py`, relay facts watch | Copy and adapt the relay watch; vendored watches when a `vendor/` comes (2.10) |
| ACME (TLS for a public listener) | `podssh-cli/src/acme/` 1,372 (TLS-ALPN-01, aws-lc-rs keys) | Later (file server or git on a public port) |
| Self-hosted relay and mailbox | `podssh-relay/src/serve/` 11,793 (+ `mailbox/` 629) + `podssh-cli/src/relay_serve/` 1,730 | Owner decision; later |

### 2.1 The TODO tool

podssh.md section 1 gives the model, the entry format and the checks. This
section adds the copy facts.

* Files: `crates/podssh-todo/src/` 16 files, 3,612 lines; `tests/` 12 files,
  1,416 lines. `interop/` (564 lines: `mod.rs` 191, `score.rs` 86,
  `words.rs` 287) and `tests/interop.rs` (204) are podssh-only.
* The whole crate builds clippy-clean on Rust 1.97 and its tests pass
  outside podssh, except the 4 tests that read podssh's own record (trial).
* `check` always runs `refs`, `github`, `claims`, `prove` (done entries)
  and `numbers`. With a new record these checks pass. Copy the whole crate
  minus `interop/` in one commit. This is less work than a subset (podssh.md
  proposed a minimum version of about 2,050 lines; deleting `claims`,
  `numbers`, `prove`, `remap` means edits in `check.rs` and `lib.rs`).
* Adaptation (about 60 changed lines):
  * Rename `podssh-todo` to `podnet-todo` (`Cargo.toml`, `USAGE` in
    `lib.rs:26`, messages in `lib.rs`, test fixtures in `numbers.rs`,
    `refs.rs`).
  * `model.rs:11` `MILESTONES`: podnet's set (owner question, podssh.md Q2).
  * `refs.rs:19` `TOP_DIRS`: add `src`, `tests`, `shim`, `fuzz`, `examples`,
    `tools`, `images`, `notebooks`; `refs.rs:20` `ROOT_FILES`: add
    `CLAUDE.md`, `build.rs`, `deny.toml`, `about.toml`, `cliff.toml`.
  * `refs.rs:43` `documents()`: add `CLAUDE.md` and `crates/*/README.md`;
    leave out `docs/releases/` and `docs/reports/` (history, with old
    paths).
  * `prove.rs:23` `Packages::of`: read the root package (`Cargo.toml` at the
    root has a `[package]` in cfrs; podssh has none) and `fuzz/`.
  * Delete `lib.rs` lines of the `interop` command, `src/interop/`,
    `tests/interop.rs`. Replace `tests/repository.rs` with a test of the
    podnet record (`CARGO_MANIFEST_DIR/../..`).
  * `cargo fmt` (width 100): `check.rs` becomes 586 lines (over 500, under
    800).
  * The word "yet": the `claims` check reads `README.md`, `AGENTS.md`,
    `SECURITY.md`, `docs/`, `TODO/`. cfrs has 3 uses (`README.md:188`,
    `README.md:1219`, `SECURITY.md:140`). Each must name an entry or a date,
    or change.
* Alias in `.cargo/config.toml`: `[alias] todo = "run -q -p podnet-todo --"`.
* Workspace: add `crates/podnet-todo` to `members`. Keep it out of
  `default-members`, or `cargo zigbuild --release --target X` builds it for
  each release target (harmless but slower).
* CI: `cargo test -p podnet-todo` and `cargo todo check` in
  `scripts/agent/check.sh` and `ci.yml`; `cargo todo check --base HEAD~1`
  (needs `fetch-depth: 2`) only after the file splits (step B) settle, as
  podssh.md says.
* Also copy: `TODO/RULES.md` (173 lines; rewrite in STE, remove narrative),
  `scripts/check-github-numbers.py` (101), `record-issues.yml` (44, daily,
  with its `--plant-drop 1` step), the plant pair `t360-record-row.*`.
* deny: no impact. Targets: not shipped. MSRV 1.89: same.

### 2.2 File transfer

podssh has no `send`/`receive` command. It has the rendezvous parts, used to
move the keys of a pair (`podssh relay pair NAME --code`, `podssh relay join
NAME`, T-086, shipped in v1.1.0-beta.2) and to join a mesh (T-616):

| File | Lines | What | For podnet |
| --- | --- | --- | --- |
| `code/mailbox.rs` | 324 | Client of the magic-wormhole mailbox protocol over a WebSocket (`wss://relay.magic-wormhole.io/v1`, then `wss://mailbox.mw.leastauthority.com/v1`) | Copy and adapt: replace `podssh_ws::session::RelaySession` with tokio-tungstenite messages and `egress::dial` (proxy) |
| `code/wormhole.rs` | 385 | magic-wormhole client protocol: SPAKE2 (`spake2 0.4`, Ed25519 group, AppID identity), phases sealed with SecretBox (`crypto_secretbox`, XSalsa20-Poly1305) under HKDF keys | Copy; change the AppID constant |
| `code/phrase.rs`, `code/words.rs` | 170, 123 | The code: nameplate + 3 words of the PGP list (24 bits) | Copy |
| `code/mod.rs` | 183 | Constants (`APPID = "github.com/Azathothas/podssh/pair"`, `MAILBOXES`, `ENV = "PODSSH_PAIR_MAILBOX"`, `LIFETIME` 600 s, `WORDS` 3), `Failed` | Adapt names to podnet (`PODNET_MAILBOX`, AppID of podnet) |
| `code/run.rs`, `code/exchange.rs` | 383, 256 | The pairing run and its JSON words (pair parts, node keys) | Reimplement as a file offer (names, sizes, SHA-256, roads) |
| `transit/` | 1,013 (6 files) | Transit relay carrier: the relay's line protocol (`please relay TOKEN for side SIDE`), then podssh's own hello and proof; token and proof key by HKDF from the pair's connect token | Copy and adapt: derive the token and the proof key from the PAKE key in place of the connect token |
| `serve/mailbox/` | 629 | A mailbox server in podssh's relay role | Later (with a self-hosted relay) |
| `scripts/wormhole-peer.py`, `pair-code.yml` | 62, 49 | Interop test with magic-wormhole's Python library and mailbox server on the loopback, then a short live run | Copy the pattern for the transfer tests |

Tests: `src/code/*` 23 unit tests, `tests/pair_code.rs` (302) +
`mailbox_harness/`, `tests/transit.rs` (340) + `transit_server/` (against
`magic-wormhole-transit-relay` 0.5.0): 17 integration tests.

The transfer command itself (offer, tar stream, record sealing with offsets,
race of roads: relay reverse, quick tunnel, transit, LAN) is new code.
capabilities.md estimates 3,000 lines with tests; with the podssh parts, the
new code is about 1,800 lines.

Wire choice (owner question): podssh's phases and transit words are
podssh's own after the magic-wormhole parts. Interop with `wormhole send`
needs the magic-wormhole file-transfer protocol (its AppID, `transit`
hints, its transit handshake and records), which podssh does not have.

### 2.3 The resumable layer, T-155, end-to-end channel, identity

| Module | Lines | Depends on | Copy |
| --- | --- | --- | --- |
| `session/` | 7,468 (31 files) | tokio, sha2, hmac, hkdf, x25519-dalek 3, rand, zeroize; `podssh_ws::text::one_line`, `podssh_ws::wake`, `crate::open::backoff` | Copy all but `handover/` (503) and `keep/handover.rs` (145), which hand a node's sessions to a new binary (T-668): about 6,820 lines. Proven standalone (trial) |
| `e2e/` | 3,376 + tests in `src` | snow 0.10, identity, session; `podssh_ws::names`, `podssh_ws::text` | Copy the core: `mod.rs` 157, `frame.rs` 165, `channel.rs` 192, `channel/carry.rs` 211, `handshake.rs` 455, `ends.rs` 340, `ask.rs` 173 (about 1,700). Leave out `net.rs` (mesh document), `legs.rs` (relay-role tokens), `person.rs`, `hold/` (handover) |
| `identity/` | 694 (4 files) | ed25519-dalek 2, hkdf, sha2, base64; `crate::cache` (private files) | Copy and adapt: ed25519-dalek 3 (in the cfrs lock); cfrs private-file helpers (`warp::private_file`, `pod_netns::listen::private_dir`) |
| `udp/` | 352 | tokio; `podssh_ws::resolve` | Copy and adapt (UDP targets for `relay node`); same idea as cfrs `upstream.rs` 0x83 frames |

What the layer gives (podssh `docs/design.md` section 5, measured in
`docs/STATUS.md`): 64-bit offsets each way, a session id and a 256-bit
secret, resume through any road with two proofs, a replay buffer (4 MiB,
`PODSSH_REPLAY_BUFFER` up to 16 MiB), heartbeat (a record each 10 s, a link
dead after 30 s), `RETIRE` and the move before the relay limits (T-155: at
48 MiB or 11 h a second link opens beside the first; the move happens at a
record boundary), the newest resume wins (T-270), half-close (T-632),
deadlines (T-306), a race of roads (`session::race`). In podssh release
binaries (the notes of v1.0.0-beta.2 name it). Tests: 117 integration tests in 21 files (6,021
lines); 18 files are self-contained and pass in the trial.

Where it applies in podnet:

* The relay reverse road (`relay node` and `relay connect`): both ends are
  podnet, so the layer runs per session, above the 32-hex-id framing of
  `src/relay_reverse.rs`. The node side is `session::far::serve` with the
  target as the opener; the operator side is `session::client` +
  `session::resume` with a link maker that opens `/v1/connect/NAME` again.
  This is capabilities.md enabler 6.5 (git over the relay, transfer).
* Not the forward road: the far end of `warp nc --via-relay`, the
  http2+relay edge leg and MASQUE through the relay is the relay Worker, not
  podnet. These cannot resume at the layer; they reconnect as today.
* The layer carries opaque bytes. The relay sees plain bytes unless the
  e2e channel runs above it (podssh runs it by default). e2e needs keys:
  `--key`, `--allow` (node allowlist) and pins on the operator side
  (identity). This is new user surface (owner question).
* Wire compatibility with podssh nodes and operators is possible if podnet
  keeps the record codes, the handshake, the Noise parameters and the
  magic values. A test against a podssh release binary in CI proves it.

### 2.4 The WebSocket relay client and the carriers

cfrs: `src/ws_relay.rs` (995: hosts, mint, token cache, `RelayBudget`,
race of hosts), `src/relay_pool.rs` (380), `src/relay_reverse.rs` (1,139:
pair, node, connect, plain bytes, one target, no resume). podssh's relay
client is larger and more complete (rank of hosts T-606/T-607, a gate per
origin T-637, cleartext road T-326, HTTP/2 extended CONNECT T-321, HTTP road
T-319, QUIC road T-667, signed mints T-448), but it is built on `podssh-ws`
(its own WebSocket client, dial, proxies, DoH and pure-Rust TLS provider).
A port of it means a port of `podssh-ws` too (24,776 lines), which
duplicates cfrs `egress`, `resolve`, `trust` and the ring provider. Keep the
cfrs client. Take ideas as TODO entries: the rank, the per-origin gate, the
cleartext road (needs relay support).

Carriers of `podssh-ws` that cfrs lacks (egress "bring your own network";
each is a `Dialer` after step F):

| podssh | Lines (ws + cli) | Gap in cfrs | Adaptation |
| --- | --- | --- | --- |
| `via/` (HTTPS forward proxy over TLS, HTTP/1.1 and HTTP/2 CONNECT) | 811 + 509 | `src/egress.rs:232` refuses `https://` proxies | Replace `podssh_ws::dial` with `egress::dial`, TLS with tokio-rustls + ring; credentials from a file. M |
| `vless/` (WebSocket and XHTTP) | 1,527 + 364 | none | uuid (in cfrs), h2 (in cfrs). M |
| `wstunnel/` | 696 + 529 | none | JWT HS256 with hmac/sha2 (in cfrs). S |
| `wisp/` | 1,331 | none | S-M |
| `shadowsocks/` (AEAD) | 1,183 + 784 | none | Use ring AES-GCM and ChaCha20-Poly1305 in place of aes-gcm/chacha20poly1305; md5 0.8 and sha1 0.11 are in cfrs. M |
| `cloudflare.rs` (`cloudflared access tcp` client) | 185 | `connect -L` speaks only the cfrs forward (`/__cfrs/ws`) | S |
| `forwarder/` | 816 + 997 | none | Later |
| `meek`, `webtunnel` (Tor pluggable transports) | 474 + 272 | none | Only with a Tor adapter |

### 2.5 Tailscale in process, and the headscale harness

* `crates/podssh-ts` (895 src, 899 tests, 46 tests) over
  `vendor/tailscale-rs` (70,135 lines in 40 manifests, edition 2024,
  MSRV 1.92). 29 patches: DERP over WebSocket (0001-0009), DERP only, no UDP
  (0011), HTTP CONNECT and SOCKS5 dial (0010, 0017, 0022), reconnect (0019),
  logout (0016), TLS provider named (0018, aws-lc-rs), test CA (0027).
  Upstream declines outside PRs (tailscale-rs #291).
* Cost for podnet: aws-lc-sys (C; cmake on some targets) through
  `ts_tls_util` (`tokio-rustls` feature `aws-lc-rs`); a second MSRV (1.92)
  for that feature; about 420 lock packages; `cargo deny` needs the ignore
  RUSTSEC-2024-0436 (`paste`) and an MPL-2.0 exception (`dyn-eq`); the
  musl/zig build for i686, arm, loongarch64, powerpc64le is not proven
  anywhere; podssh does not ship it either. A change of patch 0018 to name
  ring in place of aws-lc-rs could remove the aws-lc build (to measure).
* Verdict: later, behind an off-by-default feature, after step F
  (podssh.md open question 1). Copy then: `crates/podssh-ts` (adapt), the
  fork and `vendor/patches/` as is, `vendor/README.md` policy,
  `check-vendored.py`, `check-vendored-advisories.py`.
* Headscale harness: `scripts/ts-headscale.sh` (434) +
  `ts-headscale-lib.sh` (233) + `ts-headscale.yml` (49) +
  `images/headscale/Dockerfile`, `images/tailscale/Dockerfile` (digests).
  It starts headscale with its embedded DERP and a CA of the run, a
  tailscaled target with Tailscale SSH and a userspace tailscaled peer, in
  Podman or Docker, with pre-auth keys in files only. Copy and adapt now
  (podssh.md step 3) to test the cfrs sidecar paths with no Tailscale
  account: `cfrs net tailscale --socket` (SOCKS5/HTTP front door over the
  LocalAPI), `cfrs pod -x tailscale:SOCK -- CMD`, `cfrs net ts-shims`.
  Remove the `podssh ts`, `-W` and live-relay runs. About 400 lines. The
  plant `TS_HS_PLANT=unknown-key` stays.

### 2.6 iroh, DERP, mesh, WARP

* iroh (`podssh-iroh`, 3,640 + 1,727): QUIC between keys, n0 relays over
  HTTPS. aws-lc (C) through `tls-aws-lc-rs`, MSRV 1.91, about 520 lock
  packages, a vendored `iroh-relay` with a SOCKS5 patch. Later, behind a
  feature, owner decision.
* DERP carrier (`podssh-relay/src/derp/`, 3,543, pure Rust, `crypto_box
  0.9`): links between two keys through Tailscale's public DERP servers
  (`wss://HOST/derp`, no account) with its own ARQ under the layer. Needs
  the layer and e2e first. Later carrier for transfer and the reverse road.
  Interop proven against `derper` v1.104.4 (`scripts/interop-derp.sh`).
* Mesh (`podssh-cli/src/net/`, 3,969; `docs/mesh.md`): podssh's own node
  list, exits, routes. Skip now.
* WARP: section 2.11.

### 2.7 SSH server pieces for git hosting

podssh has no SSH server in production code (`podssh serve` is held, Q32 in
podssh `docs/design.md` section 4). `crates/podssh-cli/tests/ssh_harness/`
(20 files, 2,054 lines) is a russh 0.65 server for tests: `auth_none` for
anyone, `exec_request` of test commands, pty, `direct-tcpip`,
`direct-streamlocal`, the `sftp` subsystem (OpenSSH `sftp-server`), x11.

* For `podnet git serve --ssh`: reimplement on cfrs `russh 0.64` (its
  `server` module is compiled in, capabilities.md 1.5). Use the harness as
  an API example (Handler shape, exec and channel pumping, exit status).
* For tests: copy and adapt parts of the harness (`mod.rs`, `serve.rs`,
  `forward.rs`) as an in-test SSH server for the relay and git tests. The
  API difference 0.65 to 0.64 is small (to check at copy time). S.
* podssh's russh patches (`vendor/patches/russh/0001` to `0004`) are client
  fixes. Skip.

### 2.8 File-size and layer checks

* `scripts/check-repo.py` check 1 (`check_file_size`, lines 133-147):
  500 lines for each `crates/**/*.rs` and each `scripts/*.sh|*.py`, a floor
  of files read (a scan of nothing fails), `--plant-empty`. Copy and adapt
  as `scripts/check-size.py` (architecture.md step A2): the cfrs roots
  (`src`, `crates`, `tests`, `scripts`, `tools`), the limit (800 or 500,
  owner question), and an allowlist file of today's large files with their
  line counts that may only go down. About 100 lines.
* Also worth taking from `check-repo.py`: check 3 (key shapes: add WARP and
  WireGuard private keys, Tailscale `tskey-`), check 4 (LF in shell
  scripts), check 5 (images pinned by digest), check 9 (no panicking print
  macro in library code; cfrs has write-safe macros, so check only). cfrs
  `check-workflows.py` already has check 8 (actions pinned by commit).
* Layer check: podssh has none. Reimplement `scripts/check-layers.py` from
  `study/tools/graph.py` (architecture.md 3.4).

### 2.9 Release tooling

cfrs already has the podssh release pattern: `release.yml` with attestation
and cosign, `release-proofs.yml`, `release-short.sh`, `rebuild.sh`, the
8-target zigbuild matrix. Take:

* `scripts/fetch-zig.sh` (47) + `scripts/zig-mirrors.txt`: zig from the
  community mirrors in random order, then ziglang.org, checked by SHA-256.
  cfrs `release.yml` downloads from ziglang.org alone. Copy as is; adapt
  the path names. S.
* The mirror part of `scripts/check-release-tools.py` (74): a weekly check
  of the mirror list. S.
* Skip `release-check*.sh` (T-251): `release-proofs.yml` covers the
  after-tag checks in cfrs. Skip podssh `update-live.yml`: `live.yml` has
  the update step.

### 2.10 Upstream watch scripts

| podssh | Watches | For podnet |
| --- | --- | --- |
| `check-upstream.py` | cloudflared pin of the quick tunnel | cfrs `tools/check-upstream.py` does the same with more checks. Keep cfrs |
| `check-vendored.py`, `check-vendored-advisories.py` | New releases and advisories of the vendored copies | Copy when podnet gets a `vendor/` (tailscale-rs) |
| `check-relay-spec.py` (498) + `relay_watch.py` (155) + `relay_sections.py` (71) + `relay-watch.yml` (132) + `podssh-probe` (504 + 326) with `facts/relay-facts.toml` (108) | The relay contract at `https://tcp.ssh.relay.ajam.dev/llms-full.txt` against pinned facts; domain expiry | cfrs uses the same relay (relay commands, http2+relay leg) and has no watch. Copy and adapt: open a TODO entry in place of a GitHub issue (or print only); keep the facts file in `podnet-relay`. M |
| `check-github-numbers.py` + `record-issues.yml` | `TODO/github.txt` against GitHub | Copy with the TODO tool (2.1) |
| New: `tools/check-podssh.py` + a pin file | The podssh files that podnet copied | Write from `tools/check-upstream.py` (section 4) |

### 2.11 Overlaps with cfrs, and which to keep

| Area | cfrs | podssh | Keep | Take from podssh |
| --- | --- | --- | --- | --- |
| WARP | `src/warp/` 14,490 lines, 21 files: register, MASQUE HTTP/2 and HTTP/3, WireGuard leg, TCP and UDP on smoltcp 0.12, `warp proxy/forward/nc/run/tun/up/export`, rules, endpoint order and scan, `check_data_path` at open | `podssh-warp` 5,469: HTTP/2 only, TCP only, smoltcp 0.14, endpoint order (T-561), API routes (T-562), probe at open (T-560), record read again on a new key (T-399) | cfrs (superset; T-399, T-560, T-561, T-562 have cfrs equivalents) | `stand_in.rs` (427) + `inside.rs` (64): a fake edge on the loopback (TLS 1.3 with a pinned key, client certificate, connect-ip, smoltcp inside, routes to loopback services, counters, a "silenced" mode that takes the CONNECT and relays nothing, a key change); `src/tests/api.rs` (214, an API stand-in for `/reg`) and `tests/proxies.rs` (167, TLS server with a test CA). cfrs has only echo front doors in unit tests (for example `src/warp/session.rs:823`) and an env override `CFRS_WARP_API`. With both stand-ins, `warp register`, `warp proxy`, `warp forward`, `warp nc` get loopback tests (architecture.md 5: these are live-only today), and the "silenced" mode tests the B1 probe of mwan-field.md. Adapt to smoltcp 0.12 and cfrs types; test-only. M |
| Cloudflare tunnel | `src/cloudflare/` + `tunnel` + `edge_h2` + `quicktunnel` + `config` + `proxy`: 11,735; quick and named tunnels, QUIC (quinn) and HTTP/2, ingress rules, legs quic+warp and http2+relay | `podssh-relay/src/quick/` 6,180: quick tunnels only, for a node's WebSocket visitors; QUIC through noq | cfrs | Nothing (podssh learned from cfrs issues #5, #32, #42, #54, #57) |
| Relay client | `ws_relay`, `relay_pool`, `relay_reverse`: 2,514 | about 15,000 with `reverse/`, `pair/`, roads | cfrs client | `session/`, `e2e/` core, `identity/`, `udp/` (2.3); ideas: rank, gate, cleartext road |
| Relay server | none | `serve/` 11,793 | n/a | Owner decision (self-hosted relay) |
| Egress proxy | `egress.rs` 1,707: HTTP CONNECT (Basic, Digest), SOCKS5/5h, `unix:`, `+exec:`, `NO_PROXY`, RFC 8305 | `podssh-ws` `dial.rs`, `proxy.rs`, `socks5.rs`, MPTCP | cfrs | `via` for `https://` proxies (2.4) |
| DNS | `resolve.rs` 591: pins, system, DoH by IP and by name through the proxy | `resolve/` 2,215, ECH | cfrs | Nothing now |
| TLS | ring (rustls, quinn, rcgen) | own pure-Rust provider (no C) | cfrs (ring builds on all 8 targets with zig) | Nothing |
| Tailscale | sidecar: `pod-netns/src/tailscale.rs` LocalAPI dialer, `net tailscale`, `pod -x tailscale:`, `net ts-shims` | in-process fork (feature off, not shipped) | cfrs now; in-process later | Headscale harness now |
| WireGuard | own initiator `src/warp/wg.rs` (1,078) | none of its own | cfrs | Nothing |
| update | `update.rs` (own cosign bundle check, a CLAUDE.md ruling) | `update/` 1,744 | cfrs | Nothing |
| detach, ps, autostart | `detach.rs`, `instances.rs`, `autostart.rs` | `detach/` 3,151 | cfrs | Nothing |
| doctor, manual | `doctor.rs`, `manual/` | `doctor/` 8,302, `man/` 7,385 | cfrs | Nothing |

---

## 3. Candidates: decision, target, adaptation, size

Effort: S = up to 1 day, M = 2-4 days, L = 1-2 weeks. Sizes are of podssh
lines before reformat (add about 17 % after `cargo fmt` at width 100).

| # | Candidate | Decision | Target crate | Adaptation | New deps and `cargo deny` | 8 musl targets | Size (src + tests) | Effort |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C1 | `podssh-todo` minus `interop/` | Copy as is, then adapt constants | `crates/podnet-todo` | 2.1 | none | not shipped | 3,048 + 1,212 | S (+ M for the record import) |
| C2 | `TODO/RULES.md`, `check-github-numbers.py`, `record-issues.yml`, plant t360 | Copy and adapt (STE, no narrative) | `TODO/`, `scripts/`, `.github/` | rewrite text; paths | none | n/a | about 320 | S |
| C3 | WARP stand-in edge + API stand-in | Copy and adapt (test-only) | `src/warp/` `#[cfg(test)]` or a `stand-in` feature now; `podnet-warp` after step E | smoltcp 0.14 to 0.12 (or cfrs `WarpStack`), podssh-ws HTTP to h2/hyper-free code, cfrs `Identity`, `CFRS_WARP_API` and an endpoint override | none (rcgen, h2, rustls in cfrs) | test-only | about 900 | M |
| C4 | `session/` without handover | Copy and adapt | `podnet-relay` (`src/relay/session/` before step E) | `podssh_ws::text` to a core helper; `wake.rs` copy (Linux only); `open::backoff` to core; `PODSSH_REPLAY_BUFFER` to `PODNET_*` + manual facts; T-refs in comments to "podssh T-NNN" or removed; dated history in comments removed (CLAUDE.md "no history") | `x25519-dalek 3.0.0` (BSD-3-Clause), the only new crate | pure Rust: yes | 6,820 + about 4,900 | M |
| C5 | Resume on `relay node`/`relay connect` (T-155) | Reimplement the wiring with C4 | `podnet-relay` (`relay_reverse`) | far end per session at the node; client + resume with a new `/v1/connect/NAME` link; `-v` line per move; expiry warning from `Pair::expires` | none | yes | about 400 new + live test (200 MiB each way through the relay, crosses the 64 MiB cap) | M |
| C6 | `e2e/` core + `identity/` | Copy and adapt | `podnet-relay` | ed25519-dalek 2 to 3; `crate::cache` to cfrs private-file helpers; `podssh_ws::names` to cfrs name checks; leave out `net`, `legs`, `person`, `hold` | `snow 0.10` brings the old RustCrypto line: curve25519-dalek 4.1.3, sha2 0.10, digest 0.10, chacha20poly1305 0.10, aead 0.5 and kin (about 10 duplicate-version warnings; `multiple-versions = "warn"`; no open advisory known, run `cargo deny` at copy time). Option: own Noise XX on x25519-dalek 3 + ring AEAD + sha2/hmac (about 350 lines), checked against snow as a dev-dependency and the cacophony vectors | yes | 2,400 + about 1,000 | M |
| C7 | `udp/` | Copy and adapt | `podnet-relay` | `podssh_ws::resolve` to `resolve.rs`; UDP target for `relay node` | none | yes | 352 + 12 tests | S |
| C8 | `code/` mailbox, wormhole, phrase, words | Copy and adapt | `podnet-relay` (`rendezvous/`) | WebSocket on tokio-tungstenite + `egress::dial`; AppID, env names | `spake2 0.4` (curve25519-dalek 4, hkdf 0.12, rand_core 0.6) + `crypto_secretbox 0.1` (salsa20 0.10, poly1305 0.8): the same old line as snow; MIT/Apache. Options: `spake2 0.5.0-pre.0` (curve 5, prerelease) or own SPAKE2 on curve25519-dalek 5 (about 250 lines) | yes | 1,185 + about 600 | S-M |
| C9 | `transit/` | Copy and adapt | `podnet-relay` (`carrier/transit/`) | keys from the PAKE key; WebSocket glue | none beyond C4 | yes | 1,013 + 340 | M |
| C10 | Transfer command (offer, tar, seal, roads, CLI) | Reimplement on C4-C9 | root `podnet` (`src/cli/cmd/transfer/`) + a tar module shared with the file server in `podnet-serve` | new code | none | yes | about 1,800 new | L |
| C11 | Headscale harness | Copy and adapt | `scripts/`, `images/`, `.github/workflows/` | sidecar runs only (2.5) | none (CI images) | n/a | about 400 | M |
| C12 | Size check from `check-repo.py` check 1 (+ checks 3, 4, 5) | Copy and adapt | `scripts/check-size.py`, `scripts/check-repo.py` | roots, limit, allowlist that only shrinks, floors, `--plant-empty` | none | n/a | about 250 | S |
| C13 | `fetch-zig.sh` + `zig-mirrors.txt` + mirror check | Copy as is (names) | `scripts/`, `release.yml` | env names | none | n/a | about 150 | S |
| C14 | Relay contract watch | Copy and adapt | `podnet-relay` (facts file, test) + `scripts/` + workflow | facts of the paths cfrs uses (`/v1/pair`, `/v1/node`, `/v1/connect`, mint, limits); TODO entry in place of an issue | toml (new; pure Rust, MIT/Apache) or a hand reader | n/a | about 900 | M |
| C15 | `wormhole-peer.py` + interop job | Copy the pattern | `scripts/`, workflow | podnet AppID | none (CI venv) | n/a | about 120 | S |
| C16 | `podssh-ws` roads: `via`, `wstunnel`, `vless`, `wisp`, `shadowsocks`, `cloudflare.rs` | Copy and adapt later (after step F, each a `Dialer`) | `podnet-core` (via) or an adapter crate | `egress::dial`, ring TLS and AEAD | none (ring, h2, uuid, md5, sha1, hmac in cfrs) | yes | about 5,700 + CLI | M each |
| C17 | DERP carrier | Copy and adapt later | `podnet-relay` (`carrier/derp/`) | WebSocket glue | `crypto_box 0.9` (old line) | yes | 3,543 + tests | M-L |
| C18 | ACME client | Copy and adapt later | `podnet-serve` | aws-lc-rs keys to ring/rcgen | none | yes | 1,372 | M |
| C19 | `podssh-ts` + `vendor/tailscale-rs` + patches | Copy later behind a feature, owner decision | `crates/podnet-ts` + `vendor/` | 2.5 | aws-lc-sys (C), ~420 packages, RUSTSEC-2024-0436 ignore, MPL-2.0 exception | unproven on 4 of 8 | 1,794 + 70,135 vendored | L |
| C20 | `podssh-iroh` | Later, owner decision | adapter crate | iroh feature for ring, if any | aws-lc (C), ~520 packages | unproven | 5,367 | L |
| C21 | Relay role (`serve/` + `relay_serve/` + `mailbox/`) | Owner decision | `podnet-relay` (`serve`) | port onto cfrs HTTP stack (podssh-ws `http`, `server`, `tls_server` today) | h2 (in cfrs) | yes | about 14,000 | L+ |
| C22 | russh test server harness | Copy parts for tests | `podnet-testkit` | russh 0.65 to 0.64 API | none (russh in cfrs) | test-only | about 800 | S |
| - | Everything else (`podssh-cli` UX, `podssh-ssh`, `podssh-terminal`, `podssh-core`, `podssh-probe` as a crate, `podssh-tor`, `quick/`, `podssh-warp` road, `podssh-ws` TLS provider, DoH, proxies, detach, update, man, doctor, interop harnesses, `blocking/`, Windows and macOS code, `TODO/` content, `docs/STATUS.md`) | Skip | | podnet has its own, or does not need it | | | | |

Totals: C1-C15 and C22 (now, before or with the crate split): about 18,700
lines of src and 8,100 of tests, plus about 2,200 new lines (C5, C10).
C16-C21 (later): about 30,000 lines plus the 70,135-line fork.

### 3.1 Rules for each copy

1. One copy per commit: "Copy podssh `PATH` at `427f890` into `PATH`".
   Then the adaptation in separate commits (a reviewer sees the diff of
   the adaptation alone).
2. Rename: crate, module paths, `PODSSH_*` variables to `PODNET_*` (each
   new variable into `src/manual/facts.rs`; the test
   `each_variable_in_the_source_is_in_the_manual` enforces it), AppIDs and
   magic strings (decide per string: a changed magic breaks interop with
   podssh; section 2.3).
3. Comments: podssh comments name `T-NNN`, `Qnn` and dates. In podnet,
   write "podssh T-NNN" (as cfrs writes "podssh #118") or remove; remove
   dated narrative ("MEASURED 2026-10-02 ..."), keep the technical fact.
   Check the STE rules of `CLAUDE.md`.
4. Format with `cargo fmt` at the cfrs width; split a file that passes the
   size limit.
5. Linux only: remove `cfg(windows)` and `cfg(target_os = "macos")` code
   and the `windows-sys`, `security-framework` dependencies.
6. Messages: podssh passes a `Say` callback for user lines; cfrs uses
   tracing and the write-safe print macros. Keep `Say` at the crate edge
   or map it to tracing.
7. Private files: use the cfrs helpers (mode 0600, owner check), not
   podssh `cache::Others`.
8. Exit codes: map podssh faults to the 8 cfrs exit codes.
9. Tests: copy the tests with the code; keep their names; add the
   `need_loopback!` guard where a test binds TCP (the `restricted-host`
   job).
10. Record each copied file and its upstream SHA-256 in the pin file
    (section 4).

### 3.2 Edition and MSRV

podssh workspace: edition 2021, MSRV 1.89 (same as cfrs). `podssh-warp` and
`podssh-iroh` declare 1.91, `podssh-ts` and `podssh-tor` 1.92 (only C19
and C20 bring a higher MSRV; keep them behind features with their own MSRV
check, as podssh `gate.sh` `step_msrv_ts` does). C3 does not need 1.91 when
it moves to smoltcp 0.12. The cfrs `smoltcp = "=0.12.0"` pin and
`SMOLTCP_IFACE_MAX_ADDR_COUNT = "8"` stay.

### 3.3 Static musl, 8 targets

C1-C18 and C22 are pure Rust or use only crates that cfrs already builds
for the 8 targets (ring, rustls, h2). The added crates (x25519-dalek 3,
snow, spake2, crypto_secretbox, crypto_box, curve25519-dalek 4.1.3) are
pure Rust with portable backends (u32 on i686 and arm, u64 elsewhere).
Prove each with the release dry run (`cargo zigbuild` matrix) before the
next prerelease. C19 and C20 need aws-lc-sys (C, zig cc, cmake on some
targets): not proven on i686, arm, loongarch64, powerpc64le.

---

## 4. Share or copy

| Option | How | For | Against |
| --- | --- | --- | --- |
| A. Git dependency on podssh crates | `podssh-relay = { git = "https://github.com/Azathothas/podssh", rev = "..." }` | No copy; fixes come with a rev bump; podbox already plans this (podssh `docs/design.md` section 3) | `deny.toml` has `unknown-git = "deny"` and `allow-git = []`; `podssh-relay` needs `podssh-ws` unconditionally, which needs `rsa 0.9` (RUSTSEC-2023-0071; cfrs `ignore = []`), podssh's own crypto provider (aes-gcm, p256, p384, x25519 3, ed25519 2) beside ring; a second WebSocket, dial, DoH and TLS stack; Windows and macOS dependencies (inert on Linux); podssh names on the wire and in variables (`PODSSH_TRANSIT`, AppID `github.com/Azathothas/podssh/pair`); a rev bump drags podssh's daily changes; cargo fetches the whole podssh repository and its history (the shallow tree is 30 MB: `crates/` 21 MB, `vendor/` 12 MB, `TODO/` 4.5 MB) |
| B. Common crate on crates.io | Extract the layer (session + e2e + identity) into a small crate with no podssh-ws types; both repos depend on it | One source; registry source passes deny; a version per wire change | Rulings: cfrs "publish nothing now" (2026-11-04), podssh `publish = false`; work in podssh (a separate project and its agents); semver and release work in a third place; the layer still changes (T-668 handover, T-663 spare link in the last weeks) |
| C. Copy and own, with a pin and a watch | Copy the files into podnet crates; a pin file lists each source path, the podssh commit and the SHA-256; a weekly script compares each source path at podssh `main` with the pinned SHA-256 and names the files that changed | Full control: renames, ring, cfrs deps, Linux only, no deny change, no git source; the pattern exists in cfrs (`tools/check-upstream.py`, `src/cloudflare/cloudflared-pin.txt` with `copy` and `source` lines, `upstream.yml`); 0BSD and one owner, so no licence work | Drift: a podssh fix must be ported by hand; two copies to maintain; wire compatibility is a test, not a guarantee |

Recommendation: C, copy and own, now. Reasons: the podssh crates that podnet
needs are tied to `podssh-ws`, which duplicates cfrs and brings an advisory
that cfrs does not allow; podnet ships 8 targets and podssh 4; podnet renames
the wire and variable names; the layer still moves in podssh. Revisit B when
both projects publish and the layer's wire is stable: then extract
`session` + `e2e` + `identity` (about 9,000 lines, no podssh-ws types after
the C4/C6 adaptation) into one crate that both use. The podnet copies are the
natural start of that crate, because the adaptation removes the
`podssh-ws` types.

The watch (new, about 150 lines, from `tools/check-upstream.py`):

* `crates/podnet-relay/podssh-pin.txt` (and one beside each other copy):

  ```text
  # The podssh files that podnet copied. tools/check-podssh.py compares each
  # source with podssh main each week (.github/workflows/upstream.yml).
  repo Azathothas/podssh
  commit 427f890...
  copy crates/podssh-relay/src/session/record.rs SHA256 crates/podnet-relay/src/session/record.rs
  source crates/podssh-relay/src/session/resume.rs SHA256
  ```

* `tools/check-podssh.py`: reads podssh `main` through
  `https://forge.web.pkgforge.dev/github/repos/Azathothas/podssh/...` (the
  CLAUDE.md rule for read-only queries), prints each source whose SHA-256
  changed with the podssh commits that touched it, exit 1; exit 2 when it
  cannot read; `--plant-sum PATH` must fail (the cfrs plant rule).
* A changed file becomes a TODO entry "Port podssh change to PATH", not an
  automatic copy.
* Optional, when interop is a goal: a CI job that runs a podssh release
  binary as node or operator against podnet (both directions, through a
  stand-in relay over `ws://`; podssh's relay role can be the stand-in).

---

## 5. Ordered copy plan

It follows architecture.md 4.6: A guards, B file splits, C edge cuts,
D rename, E crate extraction, F traits. No podssh code lands during B, C,
D or E, except test-only and script items: a copy in the middle of moves
makes reviews and `git log --follow` harder.

| Step | When | Commits | Verify |
| --- | --- | --- | --- |
| A0 | First, before architecture A1 | (1) Copy `crates/podssh-todo` minus `interop/` as `crates/podnet-todo` (C1), alias, workspace member (not a default member). (2) `TODO/` skeleton: `RULES.md` (STE), `INDEX.md`, `PROGRESS.md` (State at most 20 lines, work order, parked, questions), `issues.md`, `github.txt`; `scripts/check-github-numbers.py`, `record-issues.yml` (C2). (3) `check.sh` and `ci.yml` steps | `cargo test -p podnet-todo`; `cargo todo check`; `sh scripts/agent/check.sh`; the plant t360 fails the check |
| A0b | Right after A0 | Import the entries: the 7 open issues (#89, #140, #149, #151, #161, #222, #224, text kept), the "Open work" of `docs/maintenance.md`, the lab and field items (mwan-field.md W-F1 to W-F4b, B1 to B3, router mode A/B), vn.md P1 to P5, the capability roles (capabilities.md), the architecture steps, and the podssh copies of this report (C3 to C22, each with its owner question) | `cargo todo check`; `docs/maintenance.md` "Open work" points to the record |
| A1-A2 | architecture.md | Parity snapshot; `scripts/check-size.py` from `check-repo.py` check 1 with an allowlist (C12); `scripts/check-layers.py` (new) | Each check fails once on a plant |
| A3 | Before B5 splits `src/warp/` | WARP stand-in edge + API stand-in (C3) as a test harness; loopback tests of `warp register`, `warp proxy`, `warp forward`, `warp nc` through the stand-in; a "silenced" test for the B1 data-path probe | `cargo test` count goes up; the new tests fail on a planted defect (a wrong pinned key) |
| A4 | Any time (CI only) | Headscale harness for the sidecar (C11); relay contract watch (C14); `fetch-zig.sh` + mirrors (C13, with the next release); `tools/check-podssh.py` + pin file (section 4) | Workflow runs by hand; each plant fails |
| B, C, D, E | architecture.md | No podssh code | Parity snapshot diff |
| G1 | After E (`podnet-relay` exists), in parallel with F | Copy `session/` (C4) with its 18 self-contained test files; then `e2e/` core + `identity/` (C6) with `tests/e2e.rs`, `e2e_faults.rs`, `identity_file.rs`; then `udp/` (C7) | `cargo test -p podnet-relay`; `cargo deny`; release dry run (8 targets) |
| G2 | After G1 | Resume on `relay node`/`relay connect` (C5): layer per session, move at 48 MiB or 11 h, e2e with keys (per the owner's answer) | Loopback: a fake relay with a 1 MiB cap carries 8 MiB each way with equal SHA-256 (podssh `session_move` pattern); `live.yml`: 200 MiB each way through the real relay |
| G3 | After G2 | `code/` parts (C8), `transit/` (C9), interop job with magic-wormhole (C15); then the transfer command (C10) with the tar module shared with the file server | Loopback against magic-wormhole's mailbox server and transit relay in a venv; a wrong code fails both ends and spends the code; live: 100 MiB through the public mailbox and the relay |
| H | After F (traits) | Each as an adapter behind a feature, each after an owner answer: `via` (https proxy) first, then wstunnel, VLESS, Shadowsocks, Wisp (C16); DERP carrier (C17); ACME (C18) with the file server or git on a public port; Tailscale in process (C19); iroh (C20); relay role (C21) | Per adapter: loopback test against the upstream server in CI (podssh's interop workflows show the servers: `vless-interop.yml`, `wstunnel-interop.yml`, `via-interop.yml`) |

What the next session does first (in `Azathothas/podnet`, the code still
named cfrs):

1. Read `docs/HANDOFF.md` (if it exists), `docs/maintenance.md`,
   `docs/decisions.md`, and the owner's answers to the questions below.
2. Step A0, commit 1: copy podssh `crates/podssh-todo` at `427f890`
   (without `src/interop/`, `tests/interop.rs`) to `crates/podnet-todo`;
   apply section 2.1; run `cargo test -p podnet-todo` and
   `sh scripts/agent/check.sh`; push.
3. Step A0, commits 2 and 3: the `TODO/` skeleton and the CI steps; then
   A0b, the import of the entries (from this study directory).
4. Continue with architecture.md A1 and A2.

---

## 6. Questions for the owner

1. Interop with podssh: must a podnet relay node and connect speak podssh's
   layer and e2e channel (a podssh operator reaches a podnet node, and the
   reverse)? Yes keeps the wire constants as is; no lets podnet change them.
2. Share or copy: accept "copy and own, with a pin and a weekly watch"
   (recommended), or a shared crate (git dependency now, or crates.io
   later)?
3. Crypto crates for e2e and the code: accept `snow 0.10`, `spake2 0.4` and
   `crypto_secretbox 0.1` (a second, older RustCrypto line, about 10
   duplicate-version warnings), or own Noise XX and SPAKE2 code on
   curve25519-dalek 5 and ring?
4. Transfer wire: compatible with `wormhole send` (the magic-wormhole
   file-transfer protocol, which podssh does not have), or podnet's own
   words over the wormhole mailbox? Use the public mailboxes and Least
   Authority's transit relay by default, as podssh's ruling Q65 does?
5. e2e on `relay node`/`relay connect`: on by default, with keys (`--key`,
   `--allow`, pins), as podssh does; or the layer alone first?
6. A self-hosted relay and mailbox (podssh relay role, about 14,000 lines):
   wanted in podnet?
7. Extra egress roads (`https://` proxy, wstunnel, VLESS, Shadowsocks,
   Wisp): wanted, and in which order?
8. Add podssh to the licence line of `CLAUDE.md` ("Code from
   Azathothas/podssh is 0BSD and needs no credit")?
9. From podssh.md: in-process Tailscale behind a feature (Q1); the
   milestone names and the first id of the record (Q2); the rows for the
   closed cfrs issues (Q3).
