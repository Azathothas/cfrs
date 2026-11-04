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
| 2026-11-04 | Releases | No release until the owner says go. Then triage and plan the issues that came in, as one batch. |
| 2026-11-04 | #140 | `warp proxy --l4` stays open. The work needs a captured request of an official client. |
| 2026-11-04 | #151 | ECH stays deferred: no HPKE in ring, and no hop of cfrs publishes an ECH config. |
| 2026-11-04 | #149 | Zero Trust enrolment is on hold until a captured exchange of the official client comes. |
| 2026-11-04 | WARP devices | Do not register WARP devices when it is not necessary (the service limits new devices for each address). |

## Superseded

| Date | Ruling | Superseded by |
| --- | --- | --- |
| 2026-11-01 | Releases: cut the next prerelease unattended when a batch of fixes is green. | 2026-11-04, Releases: no release until the owner says go. |

## Questions for the owner

Each question blocks a part of the work. Write the answer as a ruling
above, and remove the question.

1. **A package name for crates.io** (#161, #224): the name `cfrs` is taken
   by another project. Which name do the two crates get?
2. **A live check of the second WARP API host**: a `live.yml` step that
   registers a device through `api.devices.cloudflare.com` registers one
   device for each run. Is that acceptable, or does a read-only check
   (`GET /reg/{id}` of a saved device) do?
3. **MASQUE through the relay**: the relay ends a session at 64 MiB. The
   HTTP/2 edge leg now moves to a new connection before that. A MASQUE
   session through the relay (`warp` with the relay first) has its TCP
   flows and its egress address in one session. Is a cut at 64 MiB
   acceptable there, or do you want a planned replacement (the flows end)?
