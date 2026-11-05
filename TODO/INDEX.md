# Index

Each entry of the work record, one row each, sorted by id. The entry is in
the area file that its row links. It closes there, with its Prove run and
the result written.

`TODO/PROGRESS.md` has the only work order. `TODO/RULES.md` gives the rules
of the record. `TODO/issues.md` maps each GitHub issue to its entries.

`cargo todo set` and `cargo todo counts` derive the counts from the rows.
`cargo todo check` makes sure that the counts, the rows and the entries
agree.

## Values

**Priority.**

- **P0**: correctness fails, data is lost, or the process stops.
- **P1**: a documented capability does not work, or a flag does nothing.
- **P2**: worth doing; nothing is wrong without it.
- **P3**: worth recording, so that nobody must find it again.

**Effort.** S is less than one day. M is some days. L is one week. There
is no XL: make two entries.

**Status.** `open`, `partial`, `blocked` or `done` (`TODO/RULES.md`).

**Milestone.** `M0` to `M9`, as in `TODO/ROADMAP.md`: M0 Record, M1
Rename, M2 Split, M3 Crates, M4 Adapters, M5 Fixes, M6 Services, M7 Pods,
M8 Overlays, M9 Later.

**Category.** `defect`, `feature`, `measurement`, `release`, `chore`,
`research` or `docs`.

## Entries

**137 entries: 119 open, 1 partial, 10 blocked, 7 done.**

| Priority | open | partial | blocked | done | total |
| --- | --- | --- | --- | --- | --- |
| P0 | 0 | 0 | 0 | 0 | 0 |
| P1 | 10 | 0 | 2 | 4 | 16 |
| P2 | 81 | 1 | 6 | 3 | 91 |
| P3 | 28 | 0 | 2 | 0 | 30 |
| **All** | 119 | 1 | 10 | 7 | 137 |

| ID | Priority | Effort | Milestone | Category | Status | Item |
| --- | --- | --- | --- | --- | --- | --- |
| [T-001](deferred.md) | P3 | S | M9 | chore | blocked | Tracking: dev work in a sandbox with basic networking, and launch once and forget (GitHub #89) |
| [T-002](deferred.md) | P2 | M | M9 | feature | blocked | `warp proxy --l4`: the L4 door answers 403 to each form of the CONNECT (GitHub #140) |
| [T-003](deferred.md) | P2 | S | M9 | feature | blocked | `warp register`: enrol through a Zero Trust team token (GitHub #149) |
| [T-004](deferred.md) | P3 | M | M9 | feature | blocked | TLS: send an encrypted ClientHello on the hops that publish a config (GitHub #151) |
| [T-005](deferred.md) | P2 | S | M9 | release | blocked | crates.io: publish the library and the CLI (GitHub #161) |
| [T-006](deferred.md) | P2 | S | M9 | release | blocked | crates.io: the workspace version and the `podnet-netns` requirement are prereleases (GitHub #222) |
| [T-007](deferred.md) | P2 | S | M9 | release | blocked | crates.io: the name `cfrs` belongs to another project; choose a package name (GitHub #224) |
| [T-008](record.md) | P1 | S | M0 | chore | open | A parity snapshot: the command tree, the public items and the test list, with a diff of two runs |
| [T-009](record.md) | P1 | S | M0 | chore | done | A size check: at most 800 lines in each source file, with an allowlist that can only shrink |
| [T-010](record.md) | P1 | M | M0 | chore | open | A layer check: no module refers to a module of a higher layer, with an allowlist of 18 references that can only shrink |
| [T-011](record.md) | P2 | M | M0 | chore | open | Loopback tests for the commands that have no behaviour test, before the splits |
| [T-012](record.md) | P2 | L | M0 | chore | open | WARP stand-ins on the loopback: the registration API and a MASQUE edge, with tests of the WARP commands |
| [T-013](record.md) | P2 | S | M0 | chore | done | A daily check that the record's list of GitHub numbers agrees with GitHub |
| [T-014](record.md) | P2 | S | M0 | docs | done | The milestones M0 to M9 in a roadmap, and the open work of the maintenance page in the record |
| [T-015](record.md) | P3 | S | M2 | chore | open | CI checks that each pushed commit moved the citations of the files that it changed |
| [T-016](rename.md) | P1 | M | M1 | chore | done | Rename `cfrs` to `podnet` in the code, the tests, the workflows, the scripts and the documents |
| [T-017](rename.md) | P2 | S | M1 | docs | partial | The documents and the scripts state the facts of the old name |
| [T-018](rename.md) | P2 | S | M1 | docs | done | `CLAUDE.md` names `podnet`, its crates and the record |
| [T-019](rename.md) | P1 | M | M1 | chore | done | Drop the `pod-netns` binary, and move its integration tests to the root crate |
| [T-020](rename.md) | P1 | S | M1 | chore | done | Rename the crate `pod-netns` to `podnet-netns` |
| [T-021](rename.md) | P1 | S | M1 | chore | blocked | Verify the GitHub redirects after the transfer of the repository to PodUtils |
| [T-022](rename.md) | P1 | S | M1 | release | open | The version `0.4.0-beta.1`, and its release note with each breaking change |
| [T-023](rename.md) | P1 | S | M1 | release | open | Publish `v0.4.0-beta.1`: the dry run, the publish and the release proofs |
| [T-024](rename.md) | P2 | S | M1 | chore | open | The update checks pass against a podnet release again |
| [T-025](rename.md) | P2 | S | M1 | chore | blocked | The image `ghcr.io/podutils/podnet` is public |
| [T-026](split.md) | P2 | M | M2 | chore | open | Move the unit tests of nine files into their own files |
| [T-027](split.md) | P2 | M | M2 | chore | open | `src/main.rs` to a CLI module, part 1: the signals, the help, the argument rewrites and the shared options |
| [T-028](split.md) | P2 | M | M2 | chore | open | `src/main.rs` to a CLI module, part 2: the host commands and the `net` commands |
| [T-029](split.md) | P2 | M | M2 | chore | open | `src/main.rs` to a CLI module, part 3: the server commands |
| [T-030](split.md) | P2 | M | M2 | chore | open | `src/main.rs` to a CLI module, part 4: the WARP arguments, the client and `warp up` |
| [T-031](split.md) | P2 | M | M2 | chore | open | `src/main.rs` to a CLI module, part 5: the other WARP subcommands |
| [T-032](split.md) | P2 | M | M2 | chore | open | `src/main.rs` to a CLI module, part 6: the unit tests go to the modules that they test |
| [T-033](split.md) | P2 | M | M2 | chore | open | Split `src/egress.rs`, `src/detach.rs`, `src/update.rs` and `src/doctor.rs` |
| [T-034](split.md) | P2 | M | M2 | chore | open | Split `src/vnet/stack.rs` |
| [T-035](split.md) | P2 | M | M2 | chore | open | Split `src/warp/ip.rs`, `src/warp/session.rs` and `src/warp/wg.rs` |
| [T-036](split.md) | P2 | M | M2 | chore | open | Split `src/warp/mod.rs` and `src/warp/proxy.rs` |
| [T-037](split.md) | P2 | M | M2 | chore | open | Split `src/relay_reverse.rs` and `src/share.rs` |
| [T-038](split.md) | P2 | M | M2 | chore | open | Split `src/feature/mod.rs` and `src/proxy.rs` |
| [T-039](split.md) | P2 | M | M2 | chore | open | Split `src/edge_h2.rs` and `src/tunnel.rs` |
| [T-040](split.md) | P2 | L | M2 | chore | open | Split the seccomp backend and the netns backend of the pod crate |
| [T-041](split.md) | P2 | M | M2 | chore | open | Split the four large test files |
| [T-042](split.md) | P2 | M | M2 | chore | open | Cut the upward references 1 to 7: `net`, `util`, `fetch`, `hop`, `report`, `detach` and `relay_reverse` |
| [T-043](split.md) | P2 | M | M2 | chore | open | Cut the upward references 8, 9 and 18: a WebSocket bridge and `Metered` in the core |
| [T-044](split.md) | P2 | L | M2 | chore | open | Cut the upward references 10 to 17: the WARP QUIC configuration, `ShareLink`, `RULE_KEYS`, `connect_tunnel` and the edge side of `ws` |
| [T-045](split.md) | P2 | S | M2 | chore | open | Each file is under 800 lines, and the allowlists of the size check and the layer check are empty |
| [T-046](crates.md) | P2 | M | M3 | chore | open | Prepare the workspace for more crates: the print macros, the build facts, the scans, the package list and the test helpers |
| [T-047](crates.md) | P2 | L | M3 | chore | open | Extract the crate `podnet-core` |
| [T-048](crates.md) | P2 | M | M3 | chore | open | Extract the crate `podnet-vnet`, with the C sources of the shims |
| [T-049](crates.md) | P2 | S | M3 | chore | open | Extract the crate `podnet-relay` |
| [T-050](crates.md) | P2 | M | M3 | chore | open | Move the WARP adapter to the shared crate `pod-warp` in `PodUtils/podcrates` |
| [T-051](crates.md) | P2 | M | M3 | chore | open | Extract the crate `podnet-serve`, with the library-only modules |
| [T-052](crates.md) | P2 | M | M3 | chore | open | Move the Cloudflare adapter to the shared crate `pod-cloudflare` in `PodUtils/podcrates` |
| [T-053](crates.md) | P2 | M | M3 | chore | open | The root package is the CLI and a facade that keeps each library path |
| [T-054](crates.md) | P2 | S | M3 | release | open | A prerelease after the crate split, with the static builds of each target |
| [T-055](adapters.md) | P2 | M | M4 | feature | open | The network types in `podnet-core`: a target, a dialer, datagrams, a network and its link |
| [T-056](adapters.md) | P2 | M | M4 | feature | open | Dialers for direct, the egress proxy, the relay, the pod upstream chains, the tailnet front door and the virtual network |
| [T-057](adapters.md) | P2 | M | M4 | feature | open | A dialer and datagrams for WARP |
| [T-058](adapters.md) | P2 | M | M4 | feature | open | The combinators `Chain`, `Rules`, `Race` and `Failover` |
| [T-059](adapters.md) | P2 | M | M4 | feature | open | The registry of networks, the parser of network specs, and the rows of `doctor` |
| [T-060](adapters.md) | P2 | M | M4 | feature | open | `--via SPEC` on each command, with each old network flag as an alias |
| [T-061](adapters.md) | P2 | M | M4 | feature | open | One front door over a dialer for `warp proxy`, `pod --serve`, `net proxy` and `net tailscale` |
| [T-062](adapters.md) | P2 | M | M4 | feature | open | The service and ingress traits, with wrappers of the Cloudflare tunnel, the local listener, the relay node and the virtual network |
| [T-063](fixes.md) | P1 | M | M5 | defect | open | seccomp: a TCP socket stays tracked after its connect, and its options and addresses come from its entry |
| [T-064](fixes.md) | P1 | M | M5 | defect | open | seccomp: one entry for each socket of each process, and copies of a descriptor are tracked |
| [T-065](fixes.md) | P3 | S | M5 | feature | open | seccomp: hand a plain upstream descriptor to the program after its handshake |
| [T-066](fixes.md) | P2 | M | M5 | defect | open | seccomp: ICMP datagram sockets, `recvmmsg`, and UDP names over 255 bytes |
| [T-067](fixes.md) | P2 | M | M5 | defect | open | seccomp: a slow `connect` dial does not stop the supervisor for the other calls |
| [T-068](fixes.md) | P1 | M | M5 | defect | open | WARP: a probe of the TCP data path renews a session that carries no TCP |
| [T-069](fixes.md) | P1 | L | M5 | defect | open | `warp tun`: a SYN probe of the session, and `--session-max-age` |
| [T-070](fixes.md) | P1 | S | M5 | defect | open | `warp exec`, `warp shell` and `warp nc` find a running `warp up` with another state directory |
| [T-071](fixes.md) | P2 | M | M5 | feature | open | `warp exec` and `warp shell` take `--backend`, name the backend in one line, and log the seccomp emulation |
| [T-072](fixes.md) | P2 | S | M5 | defect | open | `warp tun` sets `rp_filter` to 0 on its interface |
| [T-073](fixes.md) | P2 | M | M5 | defect | open | `warp forward`: the pins of `--resolve`, and the list of forwards |
| [T-074](fixes.md) | P2 | L | M5 | defect | open | `warp export`: the reserved bytes in the file, `--check`, and a TCP probe on the WireGuard leg |
| [T-075](fixes.md) | P2 | S | M5 | defect | open | The datagram socket of the vnet shim takes the same user only |
| [T-076](fixes.md) | P3 | S | M5 | chore | open | A CI job runs the tests with the loopback down |
| [T-077](fixes.md) | P2 | S | M5 | defect | open | An ingress `path:` rule matches the decoded path, as cloudflared does |
| [T-078](fixes.md) | P3 | S | M5 | defect | open | `pod doctor` uses the verdict words of `doctor` and has a `schema` key |
| [T-079](fixes.md) | P3 | S | M5 | measurement | open | Read the numbers of #206 and #184 in a live run |
| [T-080](fixes.md) | P3 | M | M5 | feature | open | The errors of a config file name the line |
| [T-081](fixes.md) | P2 | S | M5 | feature | open | The tailnet front door warns when `tailscaled` is not logged in |
| [T-082](services.md) | P2 | S | M6 | feature | open | `connect --stdio` for an SSH `ProxyCommand` through `tunnel --forward` |
| [T-083](services.md) | P2 | S | M6 | feature | open | A relay node serves a handler in the process, with no socket file |
| [T-084](services.md) | P2 | M | M6 | feature | open | One HTTP authentication layer for the local listener, the tunnel and the relay |
| [T-085](services.md) | P2 | M | M6 | feature | open | A ustar writer and reader, and a directory as one tar download of the file server |
| [T-086](services.md) | P2 | L | M6 | feature | open | Copy the resumable layer, the end-to-end channel, the key identity and UDP in a stream of podssh into `podnet-relay` |
| [T-087](services.md) | P2 | M | M6 | feature | open | `relay node` and `relay connect` resume a session past the limits of the relay |
| [T-088](services.md) | P2 | S | M6 | feature | open | File server: a directory listing in HTML and JSON |
| [T-089](services.md) | P2 | M | M6 | feature | open | File server: users with read and write roles, and a PIN, on each listener |
| [T-090](services.md) | P2 | M | M6 | feature | open | File server: uploads into the served tree with PUT and a multipart form |
| [T-091](services.md) | P2 | M | M6 | feature | open | `podnet serve DIR --via`, a local `share`, a directory in `share`, and the live step of the file server |
| [T-092](services.md) | P2 | L | M6 | feature | open | Git: a CGI runner for `git http-backend`, and the smart HTTP router |
| [T-093](services.md) | P2 | M | M6 | feature | open | Git: an SSH server for upload-pack and receive-pack |
| [T-094](services.md) | P2 | M | M6 | feature | open | `podnet git serve`: the repository root, `git init`, `git urls`, the tunnel, the relay and the live step |
| [T-095](services.md) | P2 | M | M6 | feature | open | Router: several WARP identities in one process, each with its own counters |
| [T-096](services.md) | P2 | M | M6 | feature | open | Router: groups of networks with weights and a kill switch |
| [T-097](services.md) | P2 | M | M6 | feature | open | Router: a TCP health check for each member, and `podnet route status` |
| [T-098](services.md) | P2 | M | M6 | feature | open | Router: doors with a default network, and rules to a network, a group or a refusal |
| [T-099](services.md) | P2 | M | M6 | feature | open | Router: `podnet forward` for each network, UDP forwards, a DNS door, and `podnet expose` |
| [T-100](services.md) | P2 | M | M6 | feature | open | Router: a config file, and `podnet route` with `--detach` and autostart |
| [T-101](services.md) | P2 | M | M6 | measurement | open | Router: the live step with WARP, the relay and direct, and a failover |
| [T-102](services.md) | P2 | M | M6 | feature | open | Copy the mailbox client, the code words and the SPAKE2 phases of podssh |
| [T-103](services.md) | P2 | L | M6 | feature | open | The file-transfer protocol and the transit protocol of magic-wormhole |
| [T-104](services.md) | P2 | M | M6 | feature | open | The podnet relay as a carrier of a transfer |
| [T-105](services.md) | P2 | M | M6 | feature | open | `podnet send` and `podnet receive` |
| [T-106](services.md) | P2 | M | M6 | measurement | open | An interop test with the Python magic-wormhole, and the live step of a transfer of 100 MiB |
| [T-107](pods.md) | P2 | M | M7 | feature | open | seccomp: the pod lives past its first program |
| [T-108](pods.md) | P2 | S | M7 | feature | open | netns: the pod lives past its first program |
| [T-109](pods.md) | P2 | M | M7 | feature | open | `warp exec --detach --name N` keeps a pod under the supervisor |
| [T-110](pods.md) | P2 | M | M7 | feature | open | `warp exec --join N` runs a command in a detached pod |
| [T-111](pods.md) | P2 | M | M7 | feature | open | netns: generic UDP |
| [T-112](pods.md) | P3 | S | M7 | feature | open | netns: the gateway address reaches the loopback of the host, when the user asks |
| [T-113](pods.md) | P2 | S | M7 | feature | open | `warp exec` and `warp shell` try the netns backend first |
| [T-114](overlays.md) | P2 | M | M8 | chore | open | A headscale harness in CI for the `tailscaled` sidecar |
| [T-115](overlays.md) | P3 | S | M8 | feature | open | The tailnet as a network of the registry and of the router |
| [T-116](overlays.md) | P3 | S | M8 | feature | open | WireGuard: read a wg-quick file into a peer, with optional reserved bytes |
| [T-117](overlays.md) | P3 | M | M8 | feature | open | WireGuard: `wg:FILE` as a network over UDP or over a carrier |
| [T-118](overlays.md) | P3 | M | M8 | research | open | Research: NetBird, Firezone and ZeroTier as networks |
| [T-119](later.md) | P3 | M | M9 | feature | open | Router kernel mode: tables, rules and multipath routes through rtnetlink |
| [T-120](later.md) | P3 | M | M9 | feature | open | Router kernel mode: masquerade, an MSS clamp, an unreachable kill switch and `rp_filter` |
| [T-121](later.md) | P3 | S | M9 | feature | open | Router: export the groups as a JSON file of the mwan form |
| [T-122](later.md) | P3 | M | M9 | research | open | Research: a native git server with no installed `git` |
| [T-123](later.md) | P3 | M | M9 | feature | open | Tailscale in the process: copy the fork of tailscale-rs and its patches |
| [T-124](later.md) | P3 | L | M9 | feature | open | Tailscale in the process: an adapter crate behind a feature that is off by default, with the static build proven |
| [T-125](later.md) | P3 | L | M9 | feature | open | A userspace WireGuard responder: `podnet wg serve` |
| [T-126](later.md) | P3 | M | M9 | feature | open | Egress through an `https://` proxy and through wstunnel |
| [T-127](later.md) | P3 | L | M9 | feature | open | Egress through VLESS, Shadowsocks and Wisp |
| [T-128](later.md) | P3 | L | M9 | feature | open | The DERP carrier of podssh |
| [T-129](later.md) | P3 | M | M9 | feature | open | An ACME client for a public listener |
| [T-130](later.md) | P3 | M | M9 | research | open | Research: the iroh road, and a relay and mailbox of podnet's own |
| [T-131](later.md) | P3 | L | M9 | chore | open | A crate that podnet and podssh share for the layer, the channel and the identity |
| [T-132](later.md) | P3 | S | M9 | chore | open | `try_update` in place of the macro `update_atomic!` |
| [T-133](later.md) | P3 | S | M9 | chore | open | Zig from the community mirrors in the release workflow |
| [T-134](later.md) | P3 | M | M9 | chore | open | A weekly watch of the copied podssh files and of the relay contract |
| [T-135](fixes.md) | P3 | S | M5 | defect | open | `podnet pod` prints its own program name in each message and in `--version` |
| [T-136](rename.md) | P1 | S | M1 | defect | open | live: two runs in a row failed before the transfer of the repository (GitHub #311) |
| [T-137](crates.md) | P1 | M | M3 | chore | blocked | podnet uses the shared crates of `PodUtils/podcrates` |
