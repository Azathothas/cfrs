This file holds the entries of milestone M3: the extraction of the crates from the bottom up, one
crate in each commit. The owner ruled eight crates on 2026-11-05 (`docs/decisions.md`, Crates):
`podnet` (the CLI, at the root), `podnet-core`, `podnet-netns`, `podnet-vnet`, `podnet-relay`,
`podnet-warp`, `podnet-serve` and `podnet-cloudflare`. `podnet-netns` exists after T-020.
`docs/research/podnet/architecture.md`, sections 4.1, 4.2, 4.5 and 4.6 (step E), gives the
contents of each crate and the edges between them. In each commit: a new manifest with a subset
of the dependencies, a `pub use` in the root library for each old path, `pub` (with
`#[doc(hidden)]`) only where a higher crate needs an item, `fuzz/Cargo.toml` and
`fuzz/Cargo.lock`, the MSRV check of `.github/workflows/ci.yml`, and the table "The code" of
`docs/maintenance.md`.

# T-046: Prepare the workspace for more crates: the print macros, the build facts, the scans, the package list and the test helpers

**Source:** `docs/research/podnet/architecture.md`, section 4.2 (the rows Macros, Build info,
Environment scan, cargo package and Versions).
**Category:** chore
**Milestone:** M3
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Several facts of the root crate assume one library. A second library crate cannot build, or its
checks do not run, until they change.

## Premise

- The write-safe print macros and `update_atomic!` are defined in `src/lib.rs`.
- `build.rs` sets the build commit, target and date for the root crate only. `src/fetch.rs`,
  `src/report.rs`, `src/config.rs`, `src/quicktunnel.rs` and `src/tunnel.rs` read them.
- The variable scan of `src/manual/facts.rs` reads fixed directories.
- `.github/workflows/ci.yml` lists two packages for `cargo package --list`.
  `tests/docs.rs::podnet_netns_ships_the_license` checks the licence of one crate.
- `need_loopback!` and `need_localhost!` are in `tests/test_host/mod.rs`, included by
  `#[path]`. A crate cannot include a file outside its directory and still package.

## Approach

1. Define the print macros and `update_atomic!` in one macro of the core that each crate calls at
   its root, or copy their 25 lines into each crate.
2. Give the core a version function that the binary sets at start, from the build facts of
   `build.rs`.
3. Make the variable scan read `src`, each `crates/*/src` and the directory of the shims.
4. Make the package list of `ci.yml` read each member of the workspace. Check a `LICENSE` copy in
   each crate.
5. Put `need_loopback!` and `need_localhost!` into the core, behind a feature `testkit` that only
   the dev-dependencies of the crates turn on.
6. Measure the build before the split: `cargo build --timings`, and the rebuild after a touch of
   the WARP CLI module and of the egress module. Write the numbers in the Done section.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Crates): eight crates. Thus the test helpers go into
the core behind a feature, not into a ninth crate.

## Prove

```sh
sh scripts/agent/check.sh
cargo build --timings
```

## Start condition

T-045 is done.

# T-047: Extract the crate `podnet-core`

**Source:** `docs/research/podnet/architecture.md`, sections 3.2, 4.1 and 4.6, step E.
**Category:** chore
**Milestone:** M3
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

The core modules (about 11,700 lines) are in the root crate. Each edit of the CLI or of an
adapter checks them again, and the compiler does not hold the layers.

## Premise

- The core is: `exit`, `hop`, `state`, `report`, `decisions`, `metrics` (with `Metered`),
  `rlimit`, `yaml`, `race`, `util`, `qr`, `ports`; the I/O part of `net`, `trust`, `egress`,
  `proxy_auth`, `resolve`, `fetch`, `tls_fragment`, `udp`, `connect`, the WebSocket bridge of
  T-043; `detach`, `instances` and `autostart`.
- After T-045, no core module refers to a higher layer.
- A `pub use` of a moved module keeps `crate::module::Item` valid inside the root crate.

## Approach

1. Make crates/podnet-core. Move the modules with `git mv`.
2. In `src/lib.rs`, add `pub use podnet_core::{exit, state, egress, ...};` for each moved module.
3. Make `pub` (with `#[doc(hidden)]`) only the items that a higher crate needs.
4. Change the fuzz manifests, the MSRV check and the table "The code".

## Prove

```sh
sh scripts/agent/check.sh
cargo test -p podnet-core
sh scripts/agent/parity-snapshot.sh /tmp/after /tmp/before
cargo check --manifest-path fuzz/Cargo.toml --bins
gh workflow run live.yml
```

## Start condition

T-046 is done.

# T-048: Extract the crate `podnet-vnet`, with the C sources of the shims

**Source:** `docs/research/podnet/architecture.md`, sections 4.1 and 4.2 (the row cargo package).
**Category:** chore
**Milestone:** M3
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The userspace network (`src/vnet/`, about 8,400 lines) is in the root crate. Its shims are C
files under `shim/`, which `src/vnet/shim.rs` includes with `include_str!`.

## Premise

- `include_str!` must name a file inside the crate, or `cargo package` fails.
- `.github/workflows/ci.yml` checks the C file of the shim in the package list of the root
  crate.
- `podnet-vnet` depends on the core and on `podnet-netns`
  (`docs/research/podnet/architecture.md`, section 4.1).

## Approach

1. Make crates/podnet-vnet with `src/vnet/`. Move the files of `shim/` into the crate.
2. Move the package check of the shim to `podnet-vnet`.
3. Keep `tests/shim_direct.rs`, `tests/shim_no_socket.rs`, `tests/shim_socks.rs` and
   `tests/af_inet_kernel.rs` in the root crate: they run the binary.

## Prove

```sh
sh scripts/agent/check.sh
cargo test -p podnet-vnet
cargo test --test shim_direct --test shim_no_socket --test shim_socks
cargo package --list -p podnet-vnet | grep shim
```

## Start condition

T-047 is done.

# T-049: The relay client of podnet becomes the shared crate `pod-relay`

**Source:** `docs/research/podnet/architecture.md`, section 4.1.
**Category:** chore
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The relay client and the reverse road (about 2,400 lines) are in the root crate.

## Premise

- The crate takes the client of `src/ws_relay.rs` (`Relay`, `Host`, the mint, the token cache,
  `RelayBudget`, `websocket_at`), `src/relay_pool.rs` and `src/relay_reverse.rs`.
- The HTTP/2 leg through the relay stays for the Cloudflare crate (T-052).
- `tests/relay_reverse.rs` calls the library of the reverse road.

## Approach

1. Make crates/podnet-relay with these modules. It depends on the core.
2. Leave the HTTP/2 leg of `src/ws_relay.rs` in the root crate until T-052.

## Decision

The podcrates design of 2026-11-05 (`docs/decisions.md`): `podnet-relay` merges into `pod-relay` of
`PodUtils/podcrates`, with the relay client of podssh. podnet has no crate `podnet-relay`.

## Prove

```sh
sh scripts/agent/check.sh
cargo test -p podnet-relay
cargo test --test relay_reverse
gh workflow run live.yml
```

## Start condition

T-047 is done.

The shared crates exist in `PodUtils/podcrates` (T-137; the ruling "Order" of 2026-11-05 in `docs/decisions.md`).
# T-050: Move the WARP adapter to the shared crate `pod-warp` in `PodUtils/podcrates`

**Source:** `docs/research/podnet/architecture.md`, section 4.1.
**Category:** chore
**Milestone:** M3
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The WARP adapter (`src/warp/`, 21 files, about 14,500 lines) is in the root crate.

## Premise

- `podnet-warp` depends on the core, on `podnet-vnet` (`device::LinkDevice`), on `podnet-relay`
  (MASQUE through the relay) and on `podnet-netns` (the backends of `warp run`).
- The stand-ins of T-012 move with it.

## Approach

1. Move `src/warp/` to `pod-warp` in `PodUtils/podcrates`, with the stand-ins of T-012 as its tests.
2. Replace the links to the crates of podnet with traits of `pod-warp`.
3. podnet depends on `pod-warp` from crates.io, and keeps the WARP CLI in the root crate.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Shared crates): the WARP adapter moves to `PodUtils/podcrates` as `pod-warp`. A shared crate cannot depend on the crates of podnet: the links to `podnet-vnet`, `podnet-relay` and `podnet-netns` become traits of the shared crate, or move to shared crates too.

## Prove

```sh
sh scripts/agent/check.sh
cargo test -p podnet-warp
cargo test --workspace -- warp_stand_in_
gh workflow run live.yml
```

## Start condition

T-048 and T-049 are done.

The shared crates exist in `PodUtils/podcrates` (T-137; the ruling "Order" of 2026-11-05 in `docs/decisions.md`).

# T-051: Extract the crate `podnet-serve`, with the library-only modules

**Source:** `docs/research/podnet/architecture.md`, sections 3.2 and 4.1.
**Category:** chore
**Milestone:** M3
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The services (about 9,300 lines) are in the root crate. About 5,600 lines of them have no caller
in the binary.

## Premise

- The crate takes `src/share.rs`, `src/gate.rs`, `src/service.rs`, `src/ingress.rs`,
  `src/origin/`, `src/feature/`, `src/transport/`, `src/relay.rs` and the client of the
  WebSocket forward.
- `src/feature/`, `src/origin/`, `src/transport/` and `src/relay.rs` are a capability of the
  library. The owner's ruling on regressions keeps them.

## Approach

1. Make crates/podnet-serve with these modules. It depends on the core.
2. Keep each public path through the facade (`tests/api_surface.rs`).

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Regressions): no feature or capability of the code
is lost. The library-only modules stay.

## Prove

```sh
sh scripts/agent/check.sh
cargo test -p podnet-serve
cargo test --test api_surface
```

## Start condition

T-047 is done.

# T-052: Move the Cloudflare adapter to the shared crate `pod-cloudflare` in `PodUtils/podcrates`

**Source:** `docs/research/podnet/architecture.md`, sections 4.1 and 4.2 (the row cargo package).
**Category:** chore
**Milestone:** M3
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The Cloudflare tunnel (about 12,000 lines) is in the root crate. The owner made it one adapter of
podnet.

## Premise

- The crate takes `src/cloudflare/` (with `src/cloudflare/cf-edge-roots.pem`,
  `src/cloudflare/cloudflared-pin.txt` and `src/cloudflare/schemas/`), `src/tunnel.rs`,
  `src/edge_h2.rs`, `src/edge_discovery.rs`, `src/quicktunnel.rs`, `src/config.rs`,
  `src/proxy.rs`, the edge side of the WebSocket forward, the HTTP/2 leg through the relay and
  the QUIC client configuration of the quic+warp leg.
- A test of `src/cloudflare/http2.rs` includes `tools/header-oracle.txt` from outside the crate.
  A test of the trust store reads `Cargo.lock`.
- `tools/check-upstream.py` and `.github/workflows/upstream.yml` read the pin file.

## Approach

1. Move the edge client, the tunnel and the quick tunnels to `pod-cloudflare` in `PodUtils/podcrates`.
2. Replace the links to the crates of podnet with traits of `pod-cloudflare`.
3. podnet depends on `pod-cloudflare` from crates.io, and keeps the tunnel CLI in the root crate.
4. Move the two tests that read files outside the crate to the root crate of podnet.
5. Move the pin file of `tools/check-upstream.py` and the watch of `.github/workflows/upstream.yml`
   to `PodUtils/podcrates` with the edge client.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Name): the Cloudflare tunnel code is one adapter of
podnet.

The owner, 2026-11-05 (`docs/decisions.md`, Shared crates): the Cloudflare adapter (the edge client of `src/cloudflare/`, the tunnel, the quick tunnels) moves to `PodUtils/podcrates` as `pod-cloudflare`. podssh uses it for its quick tunnels.

## Prove

```sh
sh scripts/agent/check.sh
cargo test -p podnet-cloudflare
python3 -I tools/check-upstream.py
gh workflow run live.yml
```

## Start condition

T-049, T-050 and T-051 are done.

The shared crates exist in `PodUtils/podcrates` (T-137; the ruling "Order" of 2026-11-05 in `docs/decisions.md`).

# T-053: The root package is the CLI and a facade that keeps each library path

**Source:** `docs/research/podnet/architecture.md`, sections 4.1, 4.2 (the row Fuzz crate), 4.5
and 4.6, step E; `docs/research/podnet/podssh.md`, section 3 (the path map).
**Category:** chore
**Milestone:** M3
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

After T-052, the root package holds the CLI, the diagnostics and the facade. The fuzz targets
use crate-private items of several crates. No document maps each crate to its purpose.

## Premise

- The root keeps `doctor`, `preflight`, `agent`, `status`, `bug_report`, `manual`, `update` and
  `fuzzing` (`docs/research/podnet/architecture.md`, section 4.1).
- Some fuzz targets use `pub(crate)` items, for example the request head builder of the proxy
  (`src/fuzzing.rs`).
- `tests/api_surface.rs` checks the shapes of the library.

## Approach

1. Make `src/lib.rs` a facade: `pub use podnet_warp as warp;`, `pub use podnet_vnet as vnet;` and
   the other modules and root re-exports.
2. Give each crate a `#[doc(hidden)] pub mod fuzzing`. Make the facade module call them.
3. Write the path map in `docs/maintenance.md`, section "The code": each crate, its purpose and
   its main modules.
4. Measure the build again, as in T-046. Write both numbers in the Done section.

## Prove

```sh
sh scripts/agent/check.sh
cargo test --test api_surface
cargo check --manifest-path fuzz/Cargo.toml --bins
sh scripts/agent/parity-snapshot.sh /tmp/after /tmp/before
cargo build --timings
```

## Start condition

T-052 is done.

# T-054: A prerelease after the crate split, with the static builds of each target

**Source:** `docs/research/podnet/architecture.md`, section 4.2 (the rows Release build and
cargo package); `docs/maintenance.md`, section "Release"; `CLAUDE.md` (Releases).
**Category:** release
**Milestone:** M3
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The crate split changes the build of each release binary: eight crates, each with its own
dependencies, and the C shims inside a crate. Only a release run proves the eight static targets
of cargo-zigbuild and the image.

## Premise

- `.github/workflows/release.yml` builds the eight targets with cargo-zigbuild, and armv7 in
  Alpine.
- `docs/maintenance.md`, section "Release", gives the steps.

## Approach

1. Set the next version `0.4.0-beta.N`. Write its note. Its `## Breaking` says "None." for the
   command line, when the parity snapshot is empty.
2. Run the dry run, then the publish, then `release-proofs.yml`.

## Decision

The owner (`CLAUDE.md`, Releases): cut the next prerelease unattended when a batch is green.

## Prove

```sh
gh workflow run release.yml --ref main
gh workflow run release.yml --ref main -f publish=v0.4.0-beta.N
gh workflow run release-proofs.yml -f tag=v0.4.0-beta.N
```

## Start condition

T-053 is done.

# T-137: podnet uses the shared crates of `PodUtils/podcrates`

**Source:** the owner, 2026-11-05 (`docs/decisions.md`, Shared crates and Order); the proposal of
the podssh session of 2026-11-05 for `PodUtils/podcrates`.
**Category:** chore
**Milestone:** M3
**Priority:** P1
**Effort:** M
**Status:** blocked

## Problem

The ruling "Order" of 2026-11-05 holds each plan of the record until the shared crates exist.
podnet copies no code of podssh: the shared crates hold it. The WARP adapter and the Cloudflare
adapter of podnet move to the shared repository (T-050, T-052).

## Premise

- The design of `PodUtils/podcrates` (`docs/decisions.md`, podcrates design): 26 crates in four
  waves, and 8 names held only. podnet uses `pod-todo`, `pod-identity`, `pod-tls`, `pod-dns`,
  `pod-proxy`, `pod-ws`, `pod-netstack`, `pod-wg`, `pod-relay`, `pod-session`, `pod-e2e`,
  `pod-warp`, `pod-cloudflare`, `pod-wormhole`, `pod-transit` and `pod-testkit`.
- A shared crate takes a stream or dialer trait and a rustls `CryptoProvider`; the binary chooses
  the provider (podnet keeps ring). No git source: the crates come from crates.io (`deny.toml`).
- `pod-netstack` and `pod-warp` use smoltcp 0.14 and Rust 1.91: podnet pins smoltcp 0.12 and
  Rust 1.89 (`Cargo.toml`).

## Approach

1. When wave 1 exists: replace `crates/podnet-todo` with `pod-todo`, and the TLS, DNS and proxy
   code of podnet (`src/trust.rs`, `src/resolve.rs`, `src/egress.rs`) with `pod-tls`, `pod-dns`
   and `pod-proxy`.
2. When wave 2 exists: replace the relay client (`src/ws_relay.rs`, `src/relay_reverse.rs`) with
   `pod-relay` (no crate `podnet-relay`: T-049), and the userspace stack and WireGuard of
   `src/warp/` with `pod-netstack` and `pod-wg`; move to smoltcp 0.14 and Rust 1.91.
3. When wave 3 exists: replace `src/warp/` and `src/cloudflare/` with `pod-warp` and
   `pod-cloudflare` (T-050, T-052 hand their code to the podcrates session), and add
   `send`/`receive` on `pod-wormhole` and `pod-transit`.
4. Replace each copy entry of the record with its shared crate (T-012, T-086, T-102, T-114,
   T-123, T-128, T-131, T-134), and write the new order of the record in `TODO/PROGRESS.md`.

## Prove

```sh
cargo tree --workspace --depth 1
sh scripts/agent/check.sh
```

The tree shows the shared crates from crates.io.

## Blocker

The owner: create the repository `PodUtils/podcrates`, reserve the names on crates.io, and start
the podcrates session.
