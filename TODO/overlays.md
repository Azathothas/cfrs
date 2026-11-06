This file holds the entries of milestone M8: the overlay networks. The owner ruled on 2026-11-05
(`docs/decisions.md`, Tailscale): the `tailscaled` sidecar now, with a headscale harness in CI; an
in-process Tailscale later, behind a feature that is off by default (T-123, T-124). The in-process
code is `pod-ts` of `PodUtils/podcrates`. Sources: `docs/research/podnet/podssh.md`, section 2;
`docs/research/podnet/podssh-copy.md`, section 2.5 (readings).

# T-114: A headscale harness in CI for the `tailscaled` sidecar

**Source:** `docs/research/podnet/podssh.md`, section 2.3, step 3;
`docs/research/podnet/podssh-copy.md`, sections 2.5 and 3 (C11); the owner's ruling of 2026-11-05
(`docs/decisions.md`, Tailscale).
**Category:** chore
**Milestone:** M8
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The sidecar paths have no CI test with a real `tailscaled`: `net tailscale --socket`,
`pod -x tailscale:SOCK` and `net ts-shims`. CI has no Tailscale account.

## Premise

- podssh starts headscale with its embedded DERP and a CA of the run, a `tailscaled` target with
  Tailscale SSH and a userspace `tailscaled` peer, in Podman or Docker, with pre-auth keys in
  files only (`Azathothas/podssh:scripts/ts-headscale.sh`,
  `Azathothas/podssh:scripts/ts-headscale-lib.sh`,
  `Azathothas/podssh:.github/workflows/ts-headscale.yml`, and two images pinned by digest).
- The sidecar code is `crates/podnet-netns/src/tailscale.rs` and `src/vnet/tailscale_ssh.rs`.

## Approach

1. Write the harness. Read first whether `pod-testkit` of PodUtils/podcrates has a headscale harness. Take it when it has. Do not copy the scripts of podssh.
2. Add runs of `net tailscale` (SOCKS5 and HTTP CONNECT to a service of a peer), of
   `pod -x tailscale:SOCK -- curl`, and of `net ts-shims` with `tailscaled --ssh`.
3. Keep the plant `TS_HS_PLANT=unknown-key`. It must fail.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Tailscale): the `tailscaled` sidecar now, with a
headscale harness in CI.

The owner, 2026-11-05 (`docs/decisions.md`, Shared crates): the shared crates of `PodUtils/podcrates` hold this code. podnet depends on the shared crate; it does not copy the code.

## Prove

```sh
gh workflow run ts-headscale.yml
gh workflow run ts-headscale.yml -f plant=unknown-key   # must fail
```

## Start condition

The shared crate that this entry reads has a release in `PodUtils/podcrates` (T-137; `sh scripts/agent/podcrates.sh`).

## Correction

2026-11-05, podnet copies no file of podssh (`docs/decisions.md`, Shared crates). The harness is a script and a
workflow, not a crate: the shared crate that holds it is not known (`pod-testkit` is the candidate).
Ask the podcrates session before the work. The Premise lists the harness of podssh as a reading.

# T-115: The tailnet as a network of the registry and of the router

**Source:** `docs/research/podnet/podssh.md`, section 2.3, step 1;
`docs/research/podnet/capabilities.md`, section 2.1.
**Category:** feature
**Milestone:** M8
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

After M4, the tailnet dialer is a `Dialer` (T-056). It is not yet a network with a spec, a row of
`doctor` and a member of a group.

## Premise

- `pod -x tailscale:SOCK` accepts the tailnet only as the only hop.
- T-081 reads the login state of `tailscaled`.

## Approach

1. Add `tailscale:SOCK` to the registry, with the login state as its row of `doctor`.
2. Accept it in `--via`, in `--net` of the router and in a group.
3. Test it in the harness of T-114.

## Prove

```sh
cargo test --workspace -- network_spec_tailscale
gh workflow run ts-headscale.yml
```

## Start condition

T-059 and T-114 are done.

# T-116: WireGuard: read a wg-quick file into a peer, with optional reserved bytes

**Source:** `docs/research/podnet/podssh.md`, section 2.3, step 2.
**Category:** feature
**Milestone:** M8
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The WireGuard code of podnet speaks to WARP only. Its reserved bytes are fixed, and its
configuration comes from a WARP registration. A user cannot use a self-hosted peer or the export
of a VPN.

## Premise

- `src/warp/wg.rs` is an own initiator of Noise IKpsk2, with BLAKE2s and the AEAD of ring. It
  takes the reserved bytes from the `client_id` of the device.
- `src/warp/wg.rs` has a responder for its tests (`respond`).

## Approach

1. Parse a wg-quick file: `[Interface]` (PrivateKey, Address, DNS, MTU) and `[Peer]` (PublicKey,
   PresharedKey, Endpoint, AllowedIPs, PersistentKeepalive).
2. Make the reserved bytes optional, with zeros by default.
3. Read a private key from a file path only.

## Prove

```sh
cargo test --workspace -- wg_quick_file_parses wg_reserved_bytes_are_zero_by_default wg_handshake_with_the_test_responder
```

## Correction

2026-11-05, The wg-quick reader and the reserved bytes belong to the WireGuard code, which moves to `pod-wg`
(wave 2 of PodUtils/podcrates) from `src/warp/wg.rs`. Do this work in `pod-wg` after the take, or as an
issue in PodUtils/podcrates. podnet only takes the crate (T-137).

# T-117: WireGuard: `wg:FILE` as a network over UDP or over a carrier

**Source:** `docs/research/podnet/podssh.md`, section 2.3, step 2.
**Category:** feature
**Milestone:** M8
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A peer of T-116 needs a network form: a dialer over its tunnel, a spec and a carrier for hosts
with no UDP.

## Premise

- WireGuard needs UDP to its endpoint. A host behind an HTTP proxy has no UDP.
- MASQUE CONNECT-IP of WARP carries UDP (`src/warp/ip.rs`). The relay carries TCP only.

## Approach

1. Put the peer on a smoltcp stack, as the WARP leg does.
2. Send its UDP direct when a probe finds UDP, else through a WARP chain (`--via`).
3. Add `wg:FILE` to the registry.

## Prove

```sh
cargo test --workspace -- wg_network_reaches_a_service_behind_the_peer
```

A userspace responder on the loopback serves an HTTP service behind the peer.

## Start condition

T-116 and T-059 are done.

## Correction

2026-11-05, The stack is `pod-netstack` and the WireGuard code is `pod-wg` (wave 2). Step 1 puts the peer on
the smoltcp 0.14 stack of `pod-netstack`, not on a smoltcp 0.12 stack of podnet.

# T-118: Research: NetBird, Firezone and ZeroTier as networks

**Source:** `docs/research/podnet/podssh.md`, sections 2.1 and 2.3 (steps 5 and 6).
**Category:** research
**Milestone:** M8
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

podnet has no answer for NetBird, Firezone or ZeroTier. Each can need UDP, an account or a TUN.

## Premise

- podssh records them as research only (`Azathothas/podssh:docs/carriers.md`): NetBird relays over
  WebSocket on TCP 443 with a token of a management server; Firezone relays with TURN on UDP,
  behind an account; ZeroTier roots on UDP 9993, with a slow TCP fallback relay.
- Not verified: a netstack mode of NetBird with a SOCKS5 listener and no TUN; the need of the
  Firezone headless client for a TUN.

## Approach

1. For each overlay, find whether a client runs with no TUN and no root, and exposes SOCKS5 or a
   dial API; which ports it needs; and which account it needs.
2. Write the result in `docs/research/` with the commands that ran.
3. Write an entry for each overlay that passes: as a `socks5://` sidecar, or as an adapter.

## Prove

```sh
cargo todo check
```

The new entries and the research note pass the checker.
