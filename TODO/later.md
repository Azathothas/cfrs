This file holds the entries of milestone M9: the work that the owner placed after the services,
the pods and the overlays, and the work that has no ruling of the owner yet. Each entry names its
start condition. An entry with no ruling asks the owner before its work starts.

# T-119: Router kernel mode: tables, rules and multipath routes through rtnetlink

**Source:** `docs/research/podnet/mwan-field.md`, sections 1.4, 1.6 (mode B) and 4 (rank 12); the
owner's ruling of 2026-11-05 (`docs/decisions.md`, Router).
**Category:** feature
**Milestone:** M9
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

On a host with root, a user wants a kernel multi-WAN over several `warp tun` interfaces: a table
and a rule for each WAN, and a multipath default route. The route code of podnet uses ioctls only
and cannot write tables, rules or multipath routes.

## Premise

- Read: `src/warp/route.rs` adds and deletes IPv4 routes with `SIOCADDRT` and `SIOCDELRT`.
- The mwan experiment programs the kernel with the `ip` and `nft` programs, and has defects that
  podnet must not copy: a window with no rule at each interval (D3), pinned clients with no
  failover (D2), and client rules before the routes of the local subnets (D9).

## Approach

1. Write an rtnetlink writer: `RTM_NEWROUTE` with `RTA_MULTIPATH`, and `RTM_NEWRULE`. Use no
   `ip` program.
2. Make a table and a fwmark rule for each WAN, and an aggregate table with weights.
3. Replace a rule in place, with no delete before the add.
4. Put a rule `lookup main suppress_prefixlength 0` before the rules of the clients.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Router): a kernel mode for root hosts comes later.

## Prove

```sh
sudo cargo test --workspace -- route_kernel_tables_and_rules_in_a_namespace
```

The test runs in a new network namespace and compares `ip rule show` and `ip route show table N`
with the plan.

## Start condition

T-100 is done.

## Correction

2026-11-05, the route code is `src/warp/route.rs`, in the WARP adapter that moves to `pod-warp` (T-050). Read
where the code is when this entry starts.

# T-120: Router kernel mode: masquerade, an MSS clamp, an unreachable kill switch and `rp_filter`

**Source:** `docs/research/podnet/mwan-field.md`, sections 1.4 (D1, D4), 1.6 (mode B) and 2.2
(R1).
**Category:** feature
**Milestone:** M9
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

ECMP over tunnels needs a masquerade on each WAN, an MSS clamp and `rp_filter` 0. The kill switch
of the mwan experiment leaks: with no aggregate route, the kernel goes on to the main table.

## Premise

- The mwan experiment deletes the aggregate default as its kill switch (D1), and probes in its own
  namespace, not in the target namespace (D4).
- T-072 sets `rp_filter` 0 on a TUN of `warp tun`.

## Approach

1. Write the masquerade and the MSS clamp through nf_tables netlink. Use no `nft` program.
2. Put an `unreachable` default in the aggregate table as the kill switch.
3. Set `rp_filter` 0 on each WAN.
4. Probe each WAN through its session (T-068, T-069), not through the kernel routes.

## Prove

```sh
sudo cargo test --workspace -- route_kernel_kill_switch_does_not_leak
```

With each WAN down, a client of the aggregate gets "network unreachable", and no packet leaves
through the main table.

## Start condition

T-119 is done.

# T-121: Router: export the groups as a JSON file of the mwan form

**Source:** `docs/research/podnet/mwan-field.md`, sections 2.2 (R4) and 5 (question 5).
**Category:** feature
**Milestone:** M9
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The multi-WAN request asks for an export of the WANs in the JSON form of the mwan director.

## Premise

- The JSON form has `wans` (name, interface, table, weight, gateway) and `clients` (source, WAN)
  (`docs/research/podnet/mwan-field.md`, section 1.2).
- podnet routes by itself after T-100, so the export is for a host that runs the director.

## Approach

1. Add `podnet route export --format mwan-json` for the groups of `warp tun` WANs.

## Prove

```sh
cargo test --workspace -- route_export_mwan_json
```

## Start condition

T-100 is done.

# T-122: Research: a native git server with no installed `git`

**Source:** `docs/research/podnet/capabilities.md`, section 5.3 (design C); the owner's ruling of
2026-11-05 (`docs/decisions.md`, Git hosting).
**Category:** research
**Milestone:** M9
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

`podnet git serve` needs the `git` program on the host. A static podnet on a host with no `git`
cannot serve a repository.

## Premise

- `gix` has the client protocol and the pack code, but no complete server for upload-pack and
  receive-pack. `git2` (libgit2) is a C build with no server.

## Approach

1. Measure what a server on `gix` needs: protocol v2 negotiation, a pack writer, the receive and
   the ref update. Measure the size of the binary.
2. Write an entry for each part, or a question for the owner.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Git hosting): a native server comes later.

## Prove

```sh
cargo todo check
```

## Start condition

T-094 is done.

# T-123: Tailscale in the process: take the fork of tailscale-rs through `pod-ts`

**Source:** `docs/research/podnet/podssh.md`, sections 2.1 and 2.3 (step 4);
`docs/research/podnet/podssh-copy.md`, sections 2.5 and 3 (C19); the owner's ruling of 2026-11-05
(`docs/decisions.md`, Tailscale).
**Category:** feature
**Milestone:** M9
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

The tailnet works only through a `tailscaled` sidecar. A host where no `tailscaled` can run has no
tailnet.

## Premise

- podssh carries a fork of tailscale-rs at `f4781c4` with 29 patches
  (`Azathothas/podssh:vendor/tailscale-rs`, `Azathothas/podssh:vendor/patches/`), with a policy
  page and two weekly checks of the copies.
- The fork is BSD-3-Clause with PATENTS. Upstream declines outside changes.

## Approach

1. Copy the fork and its patches into a vendor directory, with its own workspace, out of the main
   workspace and out of the size check.
2. Write the vendor policy: the upstream, the commit, the licence, why it is copied and how to copy
   it again.
3. Copy the two checks of podssh (new upstream releases, advisories) as weekly jobs.
4. Add the notice of the licence to `THIRD_PARTY_NOTICES.md` and `about.toml`.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Tailscale): an in-process Tailscale from podssh comes
later, behind a feature that is off by default.

The owner, 2026-11-05 (`docs/decisions.md`, Shared crates): the shared crates of `PodUtils/podcrates` hold this code. podnet depends on the shared crate; it does not copy the code.

## Prove

```sh
cargo metadata --manifest-path vendor/tailscale-rs/Cargo.toml --format-version 1 > /dev/null
python3 -I scripts/check-vendored.py
```

## Start condition

T-114 is done.

The shared crates exist in `PodUtils/podcrates` (T-137; the ruling "Order" of 2026-11-05 in `docs/decisions.md`).

## Correction

2026-11-05, The work goes to `pod-ts` in PodUtils/podcrates. podnet only takes the crate (T-137). Do not do it in podnet. Do not copy code of podssh into podnet (`docs/decisions.md`, Shared crates). The code comes through PodUtils/podcrates. The fork and its patches are the code of `pod-ts` (wave 4). The
vendor policy and the weekly checks of the copies are podcrates work. The remaining work of podnet: the
feature that is off by default, and the notices of the licence (T-124).

# T-124: Tailscale in the process: an adapter crate behind a feature that is off by default, with the static build proven

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.5, 3 (C19) and 3.3; the owner's
ruling of 2026-11-05 (`docs/decisions.md`, Tailscale).
**Category:** feature
**Milestone:** M9
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

The fork of T-123 needs an adapter, flags and a proof that it builds for the targets of podnet.

## Premise

- The adapter of podssh is `Azathothas/podssh:crates/podssh-ts` (895 lines and 46 tests).
- The fork links aws-lc (C, cmake on some targets), needs Rust 1.92, and adds about 420 packages.
  No build for i686, arm, loongarch64 or powerpc64le is proven.
- `cargo deny` would need an ignore of RUSTSEC-2024-0436 (`paste`) and an MPL-2.0 exception. The
  owner's ruling keeps `cargo deny` green with no ignored advisory.

## Approach

1. Copy the adapter as a crate of podnet, behind a feature `ts` that is off by default and out of
   the default members.
2. Add the network `ts:` to the registry, with `--ts-auth-key-file`, `--ts-state`,
   `--ts-ephemeral` and `--ts-control-url`.
3. Add an MSRV check of 1.92 for the feature.
4. Build the feature for the eight targets with cargo-zigbuild. Try a patch that names ring in
   place of aws-lc.
5. Solve the advisory of `paste` with no ignore, or ask the owner.
6. Test it in the headscale harness of T-114.

## Prove

```sh
cargo test --features ts -p podnet --test ts_headscale
cargo deny check
gh workflow run release.yml --ref main
```

## Start condition

T-123 is done.

## Correction

2026-11-05, The adapter is `pod-ts` (wave 4 of PodUtils/podcrates), not a copy of `podssh-ts`. Step 1 becomes:
take `pod-ts` behind the feature `ts`, off by default. The MSRV check of 1.92 in step 3 is not necessary:
the toolchain is Rust 1.99 and `rust-version` is 1.99. A dependency by a git tag needs `allow-git` in
`deny.toml` (it has it for podcrates).

# T-125: A userspace WireGuard responder: `podnet wg serve`

**Source:** `docs/research/podnet/vn.md`, sections 3.2 and 5 (question 3).
**Category:** feature
**Milestone:** M9
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

podnet can dial a WireGuard peer, but cannot be one. A WireGuard endpoint with no
`CAP_NET_ADMIN`, whose inner flows go to podnet networks, does not exist.

## Premise

- `src/warp/wg.rs` has the initiator, and a responder for its tests (`respond`).
- `src/vnet/device.rs` has a link device for smoltcp.

## Approach

1. Add the responder half: cookie replies, several peers and the timers.
2. Send each inner flow to a dialer of the registry.
3. Add `podnet wg serve` with a key file and a list of peers.

## Prove

```sh
cargo test --workspace -- wg_serve_accepts_a_peer_and_dials_its_flows
```

## Start condition

T-117 is done.

## Correction

2026-11-05, the responder half of the WireGuard code (`src/warp/wg.rs`) is in `pod-wg` (wave 2). The work goes to
`pod-wg` in PodUtils/podcrates; podnet takes it and adds `podnet wg serve` (T-137).

# T-126: Egress through an `https://` proxy and through wstunnel

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.4 and 3 (C16).
**Category:** feature
**Milestone:** M9
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

`src/egress.rs` refuses an `https://` proxy, so a host whose proxy needs TLS cannot use podnet.
podnet cannot use a wstunnel server.

## Premise

- podssh has the road `via` (an HTTPS proxy over TLS, with CONNECT over HTTP/1.1 and HTTP/2) and
  a wstunnel client (`Azathothas/podssh:crates/podssh-ws/src/via/`,
  `Azathothas/podssh:crates/podssh-ws/src/wstunnel/`).
- A wstunnel token is a JWT with HS256. `hmac` and `sha2` are dependencies.

## Approach

1. Copy and change the road `via` as a dialer: `egress::dial`, TLS with ring, credentials from a
   file.
2. Copy and change the wstunnel client as a dialer.
3. Add both to the registry.

## Prove

```sh
cargo test --workspace -- https_proxy_dialer_through_a_test_ca wstunnel_dialer_
```

## Start condition

T-059 is done.

## Correction

2026-11-05, The work goes to `pod-egress` in PodUtils/podcrates. podnet only takes the crate (T-137). Do not do it in podnet. Do not copy code of podssh into podnet (`docs/decisions.md`, Shared crates). The code comes through PodUtils/podcrates. The egress roads (`via`, wstunnel) are in the design of
`pod-egress` (wave 4). `src/egress.rs` moves to `pod-proxy`. Read both crates before the work.

# T-127: Egress through VLESS, Shadowsocks and Wisp

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.4 and 3 (C16).
**Category:** feature
**Milestone:** M9
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

podnet cannot use a VLESS, Shadowsocks or Wisp server that a user runs.

## Premise

- podssh has the three clients (`Azathothas/podssh:crates/podssh-ws/src/vless/`,
  `Azathothas/podssh:crates/podssh-ws/src/shadowsocks/`,
  `Azathothas/podssh:crates/podssh-ws/src/wisp/`).
- podssh uses RustCrypto AEAD crates. podnet has the AEAD of ring.

## Approach

1. Copy and change each client as a dialer, one commit for each. Use the AEAD of ring.
2. Add each to the registry. Test each against its server in a workflow.

## Prove

```sh
cargo test --workspace -- vless_dialer_ shadowsocks_dialer_ wisp_dialer_
```

## Start condition

T-059 is done.

## Correction

2026-11-05, The work goes to `pod-egress` in PodUtils/podcrates. podnet only takes the crate (T-137). Do not do it in podnet. Do not copy code of podssh into podnet (`docs/decisions.md`, Shared crates). The code comes through PodUtils/podcrates. The Approach says "copy": it means "take from the shared crate".

# T-128: The DERP carrier through `pod-derp`

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.6 and 3 (C17).
**Category:** feature
**Milestone:** M9
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

Two podnet hosts can meet only through the podnet relay or a quick tunnel. The public DERP servers
of Tailscale need no account and run on TCP 443.

## Premise

- podssh has a DERP carrier between two keys, with its own ARQ under the resumable layer
  (`Azathothas/podssh:crates/podssh-relay/src/derp/`, 3,543 lines). It needs `crypto_box 0.9`.

## Approach

1. Take `pod-derp` of PodUtils/podcrates. Write the glue to the relay client (`pod-relay`).
2. Use it as a carrier of the layer of T-086 and of a transfer.
3. Test it against `derper` in a workflow.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Shared crates): the shared crates of `PodUtils/podcrates` hold this code. podnet depends on the shared crate; it does not copy the code.

## Prove

```sh
cargo test --workspace -- derp_
cargo deny check
```

## Start condition

T-086 is done.

The shared crates exist in `PodUtils/podcrates` (T-137; the ruling "Order" of 2026-11-05 in `docs/decisions.md`).

## Correction

2026-11-05, The work goes to `pod-derp` in PodUtils/podcrates. podnet only takes the crate (T-137). Do not do it in podnet. There is no crate `podnet-relay`: the relay client is `pod-relay`.

# T-129: An ACME client for a public listener

**Source:** `docs/research/podnet/podssh-copy.md`, section 3 (C18).
**Category:** feature
**Milestone:** M9
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

The file server and git on a public port need a certificate that browsers and git accept.

## Premise

- podssh has an ACME client with TLS-ALPN-01 and keys of aws-lc-rs
  (`Azathothas/podssh:crates/podssh-cli/src/acme/`, 1,372 lines).
- podnet has ring and rcgen.

## Approach

1. Take `pod-acme` of PodUtils/podcrates (wave 4) in `podnet-serve`. Keys come from ring and rcgen.
2. Add `--acme DOMAIN` to `serve` and `git serve` on a public TCP listener.

## Prove

```sh
cargo test -p podnet-serve -- acme_with_a_test_directory
```

The test runs against a local ACME test server (pebble) in a workflow.

## Start condition

T-091 is done.

## Correction

2026-11-05, The work goes to `pod-acme` in PodUtils/podcrates. podnet only takes the crate (T-137). Do not do it in podnet. Do not copy code of podssh into podnet (`docs/decisions.md`, Shared crates). The code comes through PodUtils/podcrates.

# T-130: Research: the iroh road, and a relay and mailbox of podnet's own

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.6 and 3 (C20, C21).
**Category:** research
**Milestone:** M9
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

podssh has an iroh road and a relay role with a mailbox. podnet has neither, and the owner has
not ruled on them.

## Premise

- The iroh road links aws-lc (C), needs Rust 1.91 and adds about 520 packages.
- The relay role of podssh has about 14,000 lines on its own HTTP stack.

## Approach

1. Measure the build of iroh with ring, if a feature allows it, and the size of the binary.
2. Measure the port of the relay role onto the HTTP stack of podnet.
3. Write a question for the owner with a recommendation, and an entry for each part that the
   owner accepts.

## Prove

```sh
cargo todo check
```

## Correction

2026-11-05, The iroh road is `pod-iroh` (wave 4 of PodUtils/podcrates) and the relay role is
`pod-relay-serve`. The toolchain is Rust 1.99, so the line "needs Rust 1.91" of the Premise is not a
constraint. The measures of the Approach stay: they decide whether podnet takes these crates.

# T-131: A crate that podnet and podssh share for the layer, the channel and the identity

**Source:** `docs/research/podnet/podssh-copy.md`, section 4 (option B); the owner's ruling of
2026-11-05 (`docs/decisions.md`, Code of podssh).
**Category:** chore
**Milestone:** M9
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

After T-086, podnet and podssh keep two copies of the resumable layer, the end-to-end channel and
the identity. A fix in one is ported by hand to the other.

## Premise

- After the changes of T-086, the copies use no podssh-ws type (about 9,000 lines).
- `deny.toml` denies git sources. The owner ruled no publish on crates.io yet.

## Approach

1. Extract the layer, the channel and the identity into one crate that both projects use.
2. Agree the source with the owner: a git dependency (which needs an allow in `deny.toml`) or a
   published crate.
3. Make podnet use it, and remove its copy.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Code of podssh): copy podssh code now; a shared crate
comes later.

The owner, 2026-11-05 (`docs/decisions.md`, Shared crates): the shared crates of `PodUtils/podcrates` hold this code. podnet depends on the shared crate; it does not copy the code.

## Prove

```sh
cargo test --workspace
cargo deny check
```

## Start condition

T-137 takes `pod-session`, `pod-e2e` and `pod-identity` (the owner chose the source: a git tag).

The shared crates exist in `PodUtils/podcrates` (T-137; the ruling "Order" of 2026-11-05 in `docs/decisions.md`).

## Correction

2026-11-05, The shared crates exist in PodUtils/podcrates: `pod-session` (the resumable layer), `pod-e2e`
(the end-to-end channel), `pod-identity` (the key identity). The owner chose the source: a git tag
(`docs/decisions.md`, Delivery of the shared crates). This entry is done by T-137, step 2. Close it
with the commit that takes `pod-session`, `pod-e2e` and `pod-identity`. podnet has no copy to remove.

# T-132: `try_update` in place of the macro `update_atomic!`

**Source:** `docs/maintenance.md`, section "Open work" (`try_update`).
**Category:** chore
**Milestone:** M9
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

`src/lib.rs` has the macro `update_atomic!`, a loop of `compare_exchange_weak`, in place of the
deprecated `fetch_update` (#214). `src/share.rs` and `src/gate.rs` use it.

## Premise

- The MSRV is 1.99 (`Cargo.toml`, `rust-version`).
- The standard library has `try_update` on the atomic types as a stable API from a later release.

## Approach

1. Replace each use of the macro with `try_update`.
2. Remove the macro.

## Prove

```sh
cargo check --workspace
sh scripts/agent/check.sh
```

The toolchain is Rust 1.99.1, the same as the MSRV.

## Start condition

The `rust-version` of `Cargo.toml` is at or above the release in which `try_update` is stable.

## Correction

2026-11-05, `try_update` is stable at Rust 1.99.1, the `rust-version` of `Cargo.toml` (a test program with
`AtomicUsize::try_update` compiles). The start condition holds. The work waits only for the ruling
"Order".

# T-133: Zig from the community mirrors in the release workflow

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.9 and 3 (C13).
**Category:** chore
**Milestone:** M9
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

`.github/workflows/release.yml` downloads zig from ziglang.org only. An outage of that site stops
a release.

## Premise

- podssh gets zig from the community mirrors in a random order, then from ziglang.org, and checks
  the SHA-256 (`Azathothas/podssh:scripts/fetch-zig.sh`,
  `Azathothas/podssh:scripts/zig-mirrors.txt`). A weekly check reads the list of mirrors.

## Approach

1. Copy the script and the list of mirrors. Change the names.
2. Use the script in `release.yml`.
3. Copy the weekly check of the mirror list.

## Prove

```sh
sh scripts/fetch-zig.sh
gh workflow run release.yml --ref main
```

# T-134: A weekly watch of the relay contract

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.10, 3 (C14) and 4.
**Category:** chore
**Milestone:** M9
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A fix of podssh in a file that podnet copied does not reach podnet. A change of the contract of
the relay (`tcp.ssh.relay.ajam.dev`) breaks the relay commands with no warning.

## Premise

- `tools/check-upstream.py` and `src/cloudflare/cloudflared-pin.txt` watch the copied parts of
  cloudflared each week (`.github/workflows/upstream.yml`).
- podssh watches the relay contract against pinned facts
  (`Azathothas/podssh:scripts/check-relay-spec.py`).
- `CLAUDE.md` says: read GitHub through the services of `https://web.pkgforge.dev/llms.txt`.

## Approach

1. Write a pin file beside each podssh copy: the source path, the podssh commit and the SHA-256.
2. Write a watch script from `tools/check-upstream.py`. It reads podssh `main` through
   `forge.web.pkgforge.dev` and names each source that changed. A changed file becomes an entry,
   not a copy. `--plant-sum` must fail.
3. Write the facts of the relay paths that podnet uses (`/v1/pair`, `/v1/node`, `/v1/connect`,
   the mint and the limits) and check them against `https://tcp.ssh.relay.ajam.dev/llms-full.txt`.
4. Run both in `.github/workflows/upstream.yml`.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Shared crates): the shared crates of `PodUtils/podcrates` hold this code. podnet depends on the shared crate; it does not copy the code.

## Prove

```sh
python3 -I tools/check-podssh.py
python3 -I tools/check-podssh.py --plant-sum   # must exit 1
gh workflow run upstream.yml
```

## Start condition

T-086 is done.

The shared crates exist in `PodUtils/podcrates` (T-137; the ruling "Order" of 2026-11-05 in `docs/decisions.md`).

## Correction

2026-11-05, podnet copies no file of podssh (`docs/decisions.md`, Shared crates), so no pin file of copied files
is necessary: steps 1 and 2 are void. A change of a shared crate comes by a git tag of PodUtils/podcrates. Step 3
(the check of the relay contract against `https://tcp.ssh.relay.ajam.dev/llms-full.txt`) stays; the
contract belongs to `pod-relay` (T-049), so check first whether podcrates has the check. The title is
changed. The Decision section keeps the ruling.

