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
| 2026-11-01 | `cfrs update` | Check SHA256SUMS, and the certificate identity and the signature of the cosign bundle over SHA256SUMS, with own code. The Rekor inclusion proof is not checked. |
| 2026-11-01 | Issues | A watcher polls for new issues. An agent triages each new issue. Close each issue with evidence (commits, CI runs, test output). |
| 2026-11-01 | Git | Work on `main` only. Push no other branch. |
| 2026-11-04 | Git | Agents that work in parallel can use local worktree branches. Their work lands on `main` as normal commits. The local branches are not pushed. |
| 2026-11-04 | Compatibility | cfrs is a beta: breaking changes are allowed. Before a stable release or a crates.io publish, weigh each breaking change. |
| 2026-11-04 | Exit codes | `wait --timeout` exits 124 at its limit. `relay connect` uses the sysexits codes of the other commands. |
| 2026-11-04 | Sockets | One rule for each Unix socket that cfrs binds: a live socket is an error (69), a file that is not a socket is an error (64), a stale socket is removed. |
| 2026-11-04 | Doctor | One verdict vocabulary for each check. |
| 2026-11-04 | State files | Root with the `HOME` of another user writes no file there by default (warning, or an error). `CFRS_FOREIGN_HOME=allow` allows it. |
| 2026-11-04 | Relay | The alternates of the default relay are the hosts of the podssh seed until a pool of `/relays.json` is cached. |
| 2026-11-04 | Releases | Cut the next prerelease unattended when a batch is green: dry run, `publish=vX`, then `release-proofs.yml`. |
| 2026-11-04 | crates.io | Publish nothing now, and choose no package name (`cfrs` is taken). Fix the packaging defects so that a publish can work. Decide again at the stable release. |
| 2026-11-04 | WARP API | A live check registers a device through the second API host (`api.devices.cloudflare.com`) and deletes it, in each live run. |
| 2026-11-04 | MASQUE through the relay | A planned replacement: at the byte or time budget of the relay, a new MASQUE session takes the new flows; the open flows end with the old session after a drain limit. |
| 2026-11-04 | #140 | `warp proxy --l4` stays open. The work needs a captured request of an official client. |
| 2026-11-04 | #151 | ECH stays deferred: no HPKE in ring, and no hop of cfrs publishes an ECH config. |
| 2026-11-04 | #149 | Zero Trust enrolment is on hold until a captured exchange of the official client comes. |
| 2026-11-04 | WARP devices | Do not register WARP devices when it is not necessary (the service limits new devices for each address). |
| 2026-11-04 | `serve --local` (#287) | `cfrs serve --local ADDR` serves the static files on a local listener (TCP or `unix:PATH`) and provisions no tunnel. |
| 2026-11-04 | pod seccomp UDP (#285) | The seccomp backend intercepts `recvfrom` and `recvmsg` on its sockets, so a UDP reader sees the real source address. A read of a connected socket stays direct. |
| 2026-11-04 | vnet sockets (#288, #289) | The unix sockets of the shim and the switch take the same user only (`SO_PEERCRED`, `SO_PASSCRED`). The switch drops a frame whose source address is not of its peer. The TCP listener of the switch needs a shared token (`CFRS_SWITCH_TOKEN` or a file). Breaking for a TCP switch with no token. |
| 2026-11-04 | QA findings | File each valid finding of the QA archive on GitHub; close the ones that are fixed on `main` at once, with the commit as evidence. |
| 2026-11-04 | Serial leg bound (#273 item 2) | The bound of a serial leg attempt comes from the budgets of the leg: the handshake and the registration with its retries. It is not a fixed 8 s. |
| 2026-11-04 | `path:` (#269 item 3) | An ingress `path:` is a regular expression, as in cloudflared. Add the `regex` dependency. |
| 2026-11-04 | Library `StaticServer` (#276 item 1) | `StaticServer` streams the body of a file of any size. The response type gets a body reader. Breaking for the library. |
| 2026-11-04 | Deferred issues | Keep #89, #140, #149, #151, #161, #222 and #224 open, each with a status comment. Close each other issue when it is fixed. |
| 2026-11-05 | Name | The project is `podnet`. The GitHub repository `Azathothas/cfrs` becomes `Azathothas/podnet`. The Cloudflare tunnel code is one adapter of podnet. |
| 2026-11-05 | Rename | A clean break: no compatibility layer (no `CFRS_*` aliases, no move of old state, no `cfrs` alias), no bridge release. The code rename is the last push of the session of 2026-11-05. The first podnet release is `v0.4.0-beta.1`, after the rename of the repository. |
| 2026-11-05 | Regressions | "No regression" means: no feature or capability of the code is lost. It does not mean compatibility for users of cfrs. A breaking change is allowed when it improves the project. |
| 2026-11-05 | pod-netns | The crate becomes `podnet-netns`, a library only. The `pod-netns` binary is dropped; `podnet pod` is the only CLI. Its integration tests move to the root crate. |
| 2026-11-05 | Crates | Eight crates: `podnet` (the CLI, at the root), `podnet-core`, `podnet-netns`, `podnet-vnet`, `podnet-relay`, `podnet-warp`, `podnet-serve`, `podnet-cloudflare`. Order: file splits, then the crate extraction from the bottom up, each commit green. |
| 2026-11-05 | File size | A source file has at most 800 lines. A script checks it in CI; the files that are larger now are in an allowlist and can only get smaller. |
| 2026-11-05 | Plan tracking | The TODO model of podssh: the record in `TODO/`, checked by the tool `podnet-todo` (a copy of `podssh-todo`) in CI. GitHub issues are an inbox: each issue becomes entries; the record keeps its text. |
| 2026-11-05 | Code of podssh | Copy podssh code into podnet and change it as necessary. A shared crate comes later. There is no wire compatibility promise with podssh. Code of podssh is 0BSD and needs no credit. |
| 2026-11-05 | File transfer | `podnet send` and `podnet receive` speak magic-wormhole (mailbox, SPAKE2, transit). The public mailbox and transit servers are the default. The podnet relay is one more carrier. |
| 2026-11-05 | Crypto crates | `snow` 0.10, `spake2` 0.4 and `crypto_secretbox` are accepted. `cargo deny` stays green with no ignored advisory. |
| 2026-11-05 | Tailscale | The `tailscaled` sidecar now, with a headscale harness in CI. An in-process Tailscale (from podssh) comes later, behind a feature that is off by default. |
| 2026-11-05 | Router | The userspace router first (per flow, no `CAP_NET_ADMIN`): groups, weights, TCP health checks, failover, a kill switch. A kernel mode for root hosts comes later. |
| 2026-11-05 | Git hosting | `podnet git serve` uses the installed `git` now (`git http-backend`, and upload-pack and receive-pack under a russh SSH server). A native server comes later. |
| 2026-11-05 | Pod backend | After the fix of the TCP sockets of the seccomp backend and generic UDP in the netns backend, `warp exec` and `warp shell` try the netns backend first, then seccomp. They get `--backend` and a line that names the backend. |
| 2026-11-05 | Live WARP devices | A live test of the router registers and deletes a WARP device in each run. |
| 2026-11-05 | crates.io | Publish nothing yet. The packaging stays ready for a publish. |

## Superseded

| Date | Ruling | Superseded by |
| --- | --- | --- |
| 2026-11-01 | Releases: cut the next prerelease unattended when a batch of fixes is green. | 2026-11-04, Releases: no release until the owner says go. |
| 2026-11-04 | Releases: no release until the owner says go. | 2026-11-04, Releases: unattended again. |

## Questions for the owner

None now. Write each new question here, with the part of the work that it
blocks.
