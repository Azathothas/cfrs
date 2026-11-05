This file holds the entries of milestone M4: one interface for the networks and for the
services, a registry of the networks, and one form of a network spec on the command line.
`docs/research/podnet/architecture.md`, section 4.3, gives the types. Each step first wraps an
API that exists, with no change of behaviour. Then the commands use the interface. Each old flag
stays (the owner's ruling of 2026-11-05 on regressions, `docs/decisions.md`).

# T-055: The network types in `podnet-core`: a target, a dialer, datagrams, a network and its link

**Source:** `docs/research/podnet/architecture.md`, section 4.3;
`docs/research/podnet/capabilities.md`, sections 2.2 and 6 (enabler 4).
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Five dial functions exist with no common interface: `egress::dial` (`src/egress.rs`), the WARP
dial of `src/warp/proxy.rs`, `Relay::connect` (`src/ws_relay.rs`), the tailnet dialer of
`crates/podnet-netns/src/tailscale.rs` and the stack of `src/vnet/stack.rs`. Each front door and
each command calls one of them by name. A router, a group or a new overlay needs one interface.

## Premise

- `docs/research/podnet/architecture.md`, section 4.3, lists for each network what it gives:
  egress, ingress, an export, or a mix.
- `WarpUdpSocket` wraps the datagrams of the WARP stack only, for quinn (`src/warp/quic.rs`).
- `futures` is a dependency (`Cargo.toml`). Boxed futures need no new crate.

## Approach

1. Add a network module to the core with these types: `Target` (a name and a port, or an
   address); `Dialer` (`label`, `tcp`, `udp`, `names_inside`); `Datagrams` (a poll to send and a
   poll to receive, so that a quinn socket can wrap it); `Network` (`scheme`, `caps`, `up`,
   `checks`); `Link` (a dialer, the exports, a status document and a close function); `Caps`.
2. Write the documentation of each type. Add unit tests with a fake dialer.

## Prove

```sh
cargo test -p podnet-core -- network::
cargo doc -p podnet-core --no-deps
```

## Start condition

T-053 is done.

# T-056: Dialers for direct, the egress proxy, the relay, the pod upstream chains, the tailnet front door and the virtual network

**Source:** `docs/research/podnet/architecture.md`, sections 4.3 and 4.6, step F.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The dial functions of T-055 have no `Dialer` form.

## Premise

- Direct and the egress proxy: `egress::dial`, `dial_direct` and `Proxy::connect`
  (`src/egress.rs`).
- The relay: `Relay::connect` reaches a public IPv4 TCP address only (`src/ws_relay.rs`).
- The pod upstream chains and the tailnet: `crates/podnet-netns/src/upstream.rs` and
  `crates/podnet-netns/src/tailscale.rs`.
- The virtual network: `NetStack` (`src/vnet/stack.rs`).

## Approach

1. Write one wrapper for each: direct, proxy, relay (TCP only; `udp` gives the default error),
   upstream chain, tailnet, virtual network.
2. Each wrapper calls the function that exists. Change no behaviour.
3. Test each wrapper on the loopback against the fakes of the tests that exist: a fake SOCKS5
   proxy, the fake relay of `tests/relay_reverse.rs`, a pair of stacks.

## Prove

```sh
cargo test --workspace -- dialer_
```

## Start condition

T-055 is done.

# T-057: A dialer and datagrams for WARP

**Source:** `docs/research/podnet/architecture.md`, section 4.3.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The WARP stack gives TCP and UDP (`WarpStack::tcp_connect`, `UdpConn` in `src/warp/ip.rs`), but
only the WARP commands and the quic+warp leg use them.

## Premise

- `src/warp/quic.rs` wraps the UDP of the WARP stack as a quinn socket for the quic+warp leg.
- The stand-ins of T-012 give a loopback edge.

## Approach

1. Write a `Dialer` over a live WARP stack, with `tcp` and `udp`.
2. Make the quinn socket of `src/warp/quic.rs` wrap any `Datagrams`, and use it for the quic+warp
   leg.
3. Test both through the edge stand-in.

## Prove

```sh
cargo test -p podnet-warp -- warp_dialer_
gh workflow run live.yml
```

## Start condition

T-055 and T-012 are done.

# T-058: The combinators `Chain`, `Rules`, `Race` and `Failover`

**Source:** `docs/research/podnet/architecture.md`, section 4.3 (the combinators).
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Each way to combine networks exists once, inside one command: MASQUE over the relay over a
proxy (`warp::Dial`, `MasqueOptions`), the rules of `warp proxy -r` (`src/warp/rules.rs`) and of
`pod -r`, `NO_PROXY`, and the staggered race of the tunnel legs (`src/race.rs`).

## Premise

- `src/race.rs` races staggered attempts and closes the losers.
- The pod rules use `RuleMatch`, which `src/warp/rules.rs` shares.

## Approach

1. `Chain`: an outer dialer carries an inner one.
2. `Rules`: a dialer for each target, first match wins, with `RuleMatch`.
3. `Race`: staggered attempts over several dialers, with `src/race.rs`.
4. `Failover`: the next dialer after an error.
5. Unit tests with fake dialers: the order, the stagger, the first rule, the failover.

## Prove

```sh
cargo test -p podnet-core -- network::chain network::rules network::race network::failover
```

## Start condition

T-056 and T-057 are done.

# T-059: The registry of networks, the parser of network specs, and the rows of `doctor`

**Source:** `docs/research/podnet/architecture.md`, sections 3.2 (the two proxy parsers) and 4.3
(the registry).
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Two parsers read a proxy URL with different schemes: `egress::Proxy::parse` (http, socks5,
socks5h, unix, +exec) and the upstream parser of the pod (socks5, http, unix, tailscale). No
table names the networks of a build.

## Premise

- `src/egress.rs` and `crates/podnet-netns/src/upstream.rs` hold the two parsers.
- `docs/research/podnet/architecture.md`, section 4.3: a static table in the binary needs no
  dependency (no `inventory`, no `linkme`) and keeps a static musl build.

## Approach

1. Add a function in the binary that returns the table of networks: one row for each enabled
   crate, with the cargo features `warp`, `cloudflare`, `relay` and `vnet`.
2. Parse specs in the form of `pod -x`: `direct`, `socks5h://...`, `http+exec:CMD`, `warp`,
   `warp:identity=PATH`, `relay:HOST`, `tailscale:/PATH`. Keep each form of both old parsers.
3. Make `doctor` read its rows from `Network::checks`.
4. Extend the fuzz target `proxy_url` to the specs.

## Prove

```sh
cargo test --workspace -- network_spec_
cargo check --manifest-path fuzz/Cargo.toml --bins
```

## Start condition

T-056 and T-057 are done.

# T-060: `--via SPEC` on each command, with each old network flag as an alias

**Source:** `docs/research/podnet/architecture.md`, sections 4.3 and 6 (question 7).
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Each command has its own network flags: `--proxy`, `--no-proxy`, `tunnel --transport`,
`warp --transport`, `warp --carry`, `pod -x` and `pod -r`. A user learns each one, and a new
network needs a new flag on each command.

## Premise

- The global flags are in `src/main.rs` (after M2, in the CLI module).
- The pod parses its own flags (`crates/podnet-netns/src/cli.rs`).

## Approach

1. Add a global `--via SPEC`, repeatable for a chain.
2. Map each old flag to a spec. Keep each old flag with its behaviour and its help.
3. Make `pod -x` and `pod -r` accept each spec of the registry.
4. Name `--via` in the manual and the help.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Regressions): no feature or capability of the code is
lost. Each old flag stays.

## Prove

```sh
cargo test --workspace -- via_alias_
cargo test --test cli -- the_man_page_names_each_flag
sh scripts/agent/parity-snapshot.sh /tmp/after /tmp/before
```

For each old flag, a unit test asserts that it builds the same chain as its spec.

## Start condition

T-059 is done.

# T-061: One front door over a dialer for `warp proxy`, `pod --serve`, `net proxy` and `net tailscale`

**Source:** `docs/research/podnet/capabilities.md`, sections 1.3 and 2.4.
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Four front doors share one parser of SOCKS5 and HTTP CONNECT (`crates/podnet-netns/src/socks.rs`),
but each has its own accept loop and its own dial side: `src/warp/proxy.rs`,
`crates/podnet-netns/src/frontdoor.rs`, `src/vnet/proxy.rs` and `crates/podnet-netns/src/tailscale.rs`.
The router of M6 needs a door over any network.

## Premise

- `docs/research/podnet/capabilities.md`, section 1.3, lists the extras of each door: UDP
  ASSOCIATE, `--dns`, rules with a reload, proxy authentication, `--l4`, `--map`, `--import` and
  `--control`.

## Approach

1. Write one door that takes a dialer: SOCKS5, HTTP CONNECT, UDP ASSOCIATE and the
   authentication.
2. Make the four commands build their dialer and call the door. Keep their extras as options of
   the door or of the command.

## Prove

```sh
cargo test --workspace -- front_door_
gh workflow run live.yml
```

The tests of the four doors that exist pass. A new test runs the door over a fake dialer.

## Start condition

T-058 is done.

# T-062: The service and ingress traits, with wrappers of the Cloudflare tunnel, the local listener, the relay node and the virtual network

**Source:** `docs/research/podnet/architecture.md`, section 4.3 (ingress and services).
**Category:** feature
**Milestone:** M4
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A service (static files, share, forward, hello, status, metrics) reaches users through the
tunnel, a local listener, a relay node or a virtual network, each with its own code. A new
service (files, git, router) needs one boundary.

## Premise

- `src/service.rs` has the enum `Built` of the built-in services. `src/ingress.rs` matches the
  rules of host and path.
- `src/proxy.rs` dispatches an axum router behind the tunnel and streams the request body.

## Approach

1. In `podnet-serve`, add `Service` (`kind`, `http`, `stream`), `Services` (the ordered rules of
   host and path), `Ingress` (`publish`) and `Published` (`url`, `ready`, `shutdown`).
2. Write the wrappers: the Cloudflare tunnel (over `TunnelBuilder`), the local listener (TCP or
   `unix:`), the relay node and a listener of the virtual network.
3. Keep `Built` as the implementation of the built-in services.
4. Add a second table in the binary for the ingress networks.

## Prove

```sh
cargo test --workspace -- ingress_
gh workflow run live.yml
```

A test serves a table of services through the local ingress on a unix socket.

## Start condition

T-055 is done.
