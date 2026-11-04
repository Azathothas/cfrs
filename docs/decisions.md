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

## Superseded

| Date | Ruling | Superseded by |
| --- | --- | --- |
| 2026-11-01 | Releases: cut the next prerelease unattended when a batch of fixes is green. | 2026-11-04, Releases: no release until the owner says go. |
| 2026-11-04 | Releases: no release until the owner says go. | 2026-11-04, Releases: unattended again. |

## Questions for the owner

None now. Write each new question here, with the part of the work that it
blocks.
