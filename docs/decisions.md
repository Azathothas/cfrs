# Decisions

The rulings of the owner, with the date of each. A ruling stays in force
until a later ruling supersedes it. Then move it to the table
"Superseded", with the ruling that replaced it. `CLAUDE.md` has the short
form of the rulings that apply to each session.

## In force

| Date | Area | Ruling |
| --- | --- | --- |
| 2026-11-01 | License | The project is 0BSD. Code from `talaria0101/cfrs` and `nemo-010/cfrs` is also 0BSD and needs no credit. |
| 2026-11-01 | Platforms | Linux only. No Windows or macOS builds. Static Linux binaries for all major architectures, with cargo-zigbuild (zig cc). |
| 2026-11-01 | Dependencies | No dependency for the edge protocol: it is in `src/cloudflare/`. |
| 2026-11-01 | Dependabot | Apply each judged update as an own commit on `main` (checks green). Close the pull request with a link to the commit. Do not merge the Dependabot branch. |
| 2026-11-01 | `podnet update` | Check SHA256SUMS, and the certificate identity and the signature of the cosign bundle over SHA256SUMS, with own code. The Rekor inclusion proof is not checked. |
| 2026-11-01 | Issues | A watcher polls for new issues. An agent triages each new issue. Close each issue with evidence (commits, CI runs, test output). |
| 2026-11-01 | Git | Work on `main` only. Push no other branch. |
| 2026-11-04 | Git | Agents that work in parallel can use local worktree branches. Their work lands on `main` as normal commits. The local branches are not pushed. |
| 2026-11-04 | Compatibility | podnet is a beta: breaking changes are allowed. Before a stable release or a crates.io publish, weigh each breaking change. |
| 2026-11-04 | Exit codes | `wait --timeout` exits 124 at its limit. `relay connect` uses the sysexits codes of the other commands. |
| 2026-11-04 | Sockets | One rule for each Unix socket that podnet binds: a live socket is an error (69), a file that is not a socket is an error (64), a stale socket is removed. |
| 2026-11-04 | Doctor | One verdict vocabulary for each check. |
| 2026-11-04 | State files | Root with the `HOME` of another user writes no file there by default (warning, or an error). `PODNET_FOREIGN_HOME=allow` allows it. |
| 2026-11-04 | Relay | The alternates of the default relay are the hosts of the podssh seed until a pool of `/relays.json` is cached. |
| 2026-11-04 | Releases | Cut the next prerelease unattended when a batch is green: dry run, `publish=vX`, then `release-proofs.yml`. |
| 2026-11-04 | crates.io | Publish nothing now, and choose no package name (`cfrs` is taken; `podnet` is free). Fix the packaging defects so that a publish can work. Decide again at the stable release. |
| 2026-11-04 | WARP API | A live check registers a device through the second API host (`api.devices.cloudflare.com`) and deletes it, in each live run. |
| 2026-11-04 | MASQUE through the relay | A planned replacement: at the byte or time budget of the relay, a new MASQUE session takes the new flows; the open flows end with the old session after a drain limit. |
| 2026-11-04 | #140 | `warp proxy --l4` stays open. The work needs a captured request of an official client. |
| 2026-11-04 | #151 | ECH stays deferred: no HPKE in ring, and no hop of podnet publishes an ECH config. |
| 2026-11-04 | #149 | Zero Trust enrolment is on hold until a captured exchange of the official client comes. |
| 2026-11-04 | WARP devices | Do not register WARP devices when it is not necessary (the service limits new devices for each address). |
| 2026-11-04 | `serve --local` (#287) | `podnet serve --local ADDR` serves the static files on a local listener (TCP or `unix:PATH`) and provisions no tunnel. |
| 2026-11-04 | pod seccomp UDP (#285) | The seccomp backend intercepts `recvfrom` and `recvmsg` on its sockets, so a UDP reader sees the real source address. A read of a connected socket stays direct. |
| 2026-11-04 | vnet sockets (#288, #289) | The unix sockets of the shim and the switch take the same user only (`SO_PEERCRED`, `SO_PASSCRED`). The switch drops a frame whose source address is not of its peer. The TCP listener of the switch needs a shared token (`PODNET_SWITCH_TOKEN` or a file). Breaking for a TCP switch with no token. |
| 2026-11-04 | QA findings | File each valid finding of the QA archive on GitHub; close the ones that are fixed on `main` at once, with the commit as evidence. |
| 2026-11-04 | Serial leg bound (#273 item 2) | The bound of a serial leg attempt comes from the budgets of the leg: the handshake and the registration with its retries. It is not a fixed 8 s. |
| 2026-11-04 | `path:` (#269 item 3) | An ingress `path:` is a regular expression, as in cloudflared. Add the `regex` dependency. |
| 2026-11-04 | Library `StaticServer` (#276 item 1) | `StaticServer` streams the body of a file of any size. The response type gets a body reader. Breaking for the library. |
| 2026-11-04 | Deferred issues | Keep #89, #140, #149, #151, #161, #222 and #224 open, each with a status comment. Close each other issue when it is fixed. |
| 2026-11-05 | Name | The project is `podnet`. The GitHub repository `Azathothas/cfrs` becomes `PodUtils/podnet`. The Cloudflare tunnel code is one adapter of podnet. |
| 2026-11-05 | Rename | A clean break: no compatibility layer (no `CFRS_*` aliases, no move of old state, no `cfrs` alias), no bridge release. The code rename is the last push of the session of 2026-11-05. The first podnet release is `v0.4.0-beta.1`, after the rename of the repository. |
| 2026-11-05 | Regressions | "No regression" means: no feature or capability of the code is lost. It does not mean compatibility for users of cfrs. A breaking change is allowed when it improves the project. |
| 2026-11-05 | pod-netns | The crate becomes `podnet-netns`, a library only. The `pod-netns` binary is dropped; `podnet pod` is the only CLI. Its integration tests move to the root crate. |
| 2026-11-05 | File size | A source file has at most 800 lines. A script checks it in CI; the files that are larger now are in an allowlist and can only get smaller. |
| 2026-11-05 | Plan tracking | The TODO model of podssh: the record in `TODO/`, checked by the tool `podnet-todo` (a copy of `podssh-todo`) in CI. GitHub issues are an inbox: each issue becomes entries; the record keeps its text. |
| 2026-11-05 | File transfer | `podnet send` and `podnet receive` speak magic-wormhole (mailbox, SPAKE2, transit). The public mailbox and transit servers are the default. The podnet relay is one more carrier. |
| 2026-11-05 | Crypto crates | `snow` 0.10, `spake2` 0.4 and `crypto_secretbox` are accepted. `cargo deny` stays green with no ignored advisory. |
| 2026-11-05 | Tailscale | The `tailscaled` sidecar now, with a headscale harness in CI. An in-process Tailscale (from podssh) comes later, behind a feature that is off by default. |
| 2026-11-05 | Router | The userspace router first (per flow, no `CAP_NET_ADMIN`): groups, weights, TCP health checks, failover, a kill switch. A kernel mode for root hosts comes later. |
| 2026-11-05 | Git hosting | `podnet git serve` uses the installed `git` now (`git http-backend`, and upload-pack and receive-pack under a russh SSH server). A native server comes later. |
| 2026-11-05 | Pod backend | After the fix of the TCP sockets of the seccomp backend and generic UDP in the netns backend, `warp exec` and `warp shell` try the netns backend first, then seccomp. They get `--backend` and a line that names the backend. |
| 2026-11-05 | Live WARP devices | A live test of the router registers and deletes a WARP device in each run. |
| 2026-11-05 | crates.io | Publish no real version yet. The owner reserves the crate names with 0.0.0 placeholders (`podnet` is reserved). The packaging stays ready for a publish. |
| 2026-11-05 | Home | Each project moves to the GitHub organization `PodUtils`: the repository is `PodUtils/podnet` (a transfer of `Azathothas/cfrs` and a rename), the image is `ghcr.io/podutils/podnet`, podssh is `PodUtils/podssh`. The certificate identity of a release is `https://github.com/PodUtils/podnet/.github/workflows/release.yml@refs/tags/TAG`. |
| 2026-11-05 | Shared crates | The repository `PodUtils/podcrates` holds the crates that the PodUtils projects share (prefix `pod-`). The WARP adapter and the Cloudflare adapter of podnet move there as `pod-warp` and `pod-cloudflare`. podnet then has five crates: `podnet`, `podnet-core`, `podnet-netns`, `podnet-vnet`, `podnet-serve`. The code of podssh comes to podnet through the shared crates, not as copies. |
| 2026-11-05 | podcrates design | Agreed between the podnet and podssh sessions at the owner's request. 26 crates in `PodUtils/podcrates`. Wave 1: `pod-todo`, `pod-identity`, `pod-term`, `pod-tls`, `pod-dns`, `pod-proxy`, `pod-ws`, `pod-testkit`. Wave 2: `pod-netstack`, `pod-wg`, `pod-relay`, `pod-session`, `pod-e2e`. Wave 3: `pod-warp`, `pod-cloudflare`, `pod-wormhole`, `pod-transit`. Wave 4: `pod-relay-serve`, `pod-derp`, `pod-acme`, `pod-egress`, `pod-iroh`, `pod-ts`, `pod-tor`, `pod-piping`, `pod-opentunnel`. Names held only: `pod-wireguard`, `pod-quick`, `pod-udp`, `pod-mailbox`, `pod-reverse`, `podcrates`, `podutils`, `pod-utils`. `podnet-relay` merges into `pod-relay`. Library crates have no C and no fixed crypto provider; the binary chooses (podnet: ring). Crates come from crates.io only. Each crate keeps the tests of its source. One new session in `PodUtils/podcrates` builds them; podnet and podssh do not edit podcrates. `pod-netstack` and `pod-warp` use smoltcp 0.14 and Rust 1.91. |
| 2026-11-05 | Order | Only the move of the repository (T-021) goes on now. There is no release `v0.4.0-beta.1` now. Each other plan of the record waits until the shared crates exist in `PodUtils/podcrates`. |
| 2026-11-05 | Delivery of the shared crates (podcrates Q1) | podnet takes each crate of `PodUtils/podcrates` by a git tag: `pod-x = { git = "https://github.com/PodUtils/podcrates", tag = "vX.Y.Z" }`. `deny.toml` has `https://github.com/PodUtils/podcrates` in `allow-git`. Not from crates.io. (Relayed by the podcrates session.) |
| 2026-11-05 | Who edits a shared crate (podcrates Q3) | (a) From the import of a module into podcrates until podnet takes its crate, podnet changes that module only for fixes, and podcrates ports each fix. (b) podnet takes a crate on the day of its release. (c) After that, a podnet session can change the crate in `PodUtils/podcrates` under the `AGENTS.md` of podcrates with its checks green, or open an issue there. |
| 2026-11-05 | Toolchain | Modern stable Rust; nightly only when it is necessary. podcrates is edition 2024 with `rust-version` 1.99 (stable 1.99.1 of 2026-10-13): podnet moves its toolchain to 1.99 when a crate needs it. Each binary is statically compiled: this is the one hard rule. |
| 2026-11-05 | crates.io names | The owner reserves each name as a 0.0.0 placeholder. `pod-*` is only for podcrates; podnet uses `podnet-*`. `podnet` is reserved; `podnet-core`, `podnet-netns`, `podnet-vnet` and `podnet-serve` wait in the queue of the owner. Ask the owner to reserve a new name before its first publish. Do not publish a new name with a token. |
| 2026-11-05 | `publish.yml` | A publish workflow `.github/workflows/publish.yml`, separate from `release.yml`. crates.io trusts the repository `PodUtils/podnet`, this file and the environment `crates-io` (tags `v*` only). No crates.io token is stored. The token comes from `rust-lang/crates-io-auth-action` (pinned to a SHA). Each run does `cargo publish --workspace --dry-run`. The real publish runs only when `[workspace.metadata.podnet] crates-io = true` at the tag; it stays false while "Publish no real version yet" is in force. |
| 2026-11-05 | Git dependencies and the publish (Q1) | Each `pod-*` dependency of a crate that can be published has `version` beside `git` and `tag`. Cargo builds from the git tag; `cargo deny` (wildcards) needs the version; crates.io takes the version. Until podcrates publishes its crates to crates.io, the dry run of `publish.yml` on a tag fails, and the switch stays false. |
| 2026-11-05 | ghcr package | The package `ghcr.io/podutils/podnet` takes the visibility of the public repository when the first release pushes it. No owner action. |
| 2026-11-05 | Shared CI scripts | A CI script that podnet and podssh share (the zig fetch with its mirrors, T-133) lives in `PodUtils/podcrates`. podnet calls it from there; it does not copy it. |
| 2026-11-05 | Relay contract watch | The weekly watch of the relay contract belongs to `pod-relay` in `PodUtils/podcrates` (T-134), not to podnet. |
| 2026-11-05 | Services crate | Each list of relays and services of other parties that podnet holds (the relay hosts, the DoH resolvers and their pins, the edge discovery, the quick-tunnel API, the WARP API and endpoints, the sources of the edge roots, STUN and NTP hosts, the GitHub hosts of `podnet update`, others), the code and the scripts that measure or watch them, the watch workflows (`live.yml` and `scripts/live-*.sh`, the reads of services in `release-proofs.yml`) and their data files move to `pod-services` of `PodUtils/podcrates` (T-137). podnet adds no new hardcoded service. Until the take, podnet changes these places only for fixes, and tells the podcrates session of each fix. The relay contract watch stays in `pod-relay`. |

## Superseded

| Date | Ruling | Superseded by |
| --- | --- | --- |
| 2026-11-01 | Releases: cut the next prerelease unattended when a batch of fixes is green. | 2026-11-04, Releases: no release until the owner says go. |
| 2026-11-04 | Releases: no release until the owner says go. | 2026-11-04, Releases: unattended again. |
| 2026-11-05 | Crates: eight crates, with `podnet-warp` and `podnet-cloudflare`. | 2026-11-05, Shared crates: five crates in podnet; `pod-warp` and `pod-cloudflare` in `PodUtils/podcrates`. |
| 2026-11-05 | Code of podssh: copy it into podnet now, a shared crate later. | 2026-11-05, Shared crates: the code comes through `PodUtils/podcrates`. |
| 2026-11-05 | Rename: the first podnet release `v0.4.0-beta.1` after the move. | 2026-11-05, Order: no release now; the plans wait for the shared crates. |
| 2026-11-05 | podcrates design: crates come from crates.io only. | 2026-11-05, Delivery of the shared crates: a git tag of `PodUtils/podcrates`. |
| 2026-11-05 | podcrates design: podnet and podssh do not edit podcrates. | 2026-11-05, Who edits a shared crate. |
| 2026-11-05 | podcrates design: Rust 1.91 for `pod-netstack` and `pod-warp`. | 2026-11-05, Toolchain: Rust 1.99 (edition 2024). |

## Questions for the owner

Write each new question here, with the part of the work that it blocks.

None now.
