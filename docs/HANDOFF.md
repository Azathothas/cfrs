# Handoff

The state of the work at the end of the session of 2026-11-04. Read this
file first, then `CLAUDE.md`, `docs/maintenance.md` and
`docs/decisions.md`. Delete this file when each item below is done, and
keep `docs/maintenance.md` "Open work" current.

## Where the code is

* `main` on GitHub has batch 4 (the podssh study), the owner rulings of
  2026-11-04 and most of batch 5. Nothing of batch 4 or 5 is released:
  the newest release is `v0.3.0-beta.11`.
* Local work that is not on `main` if this session stopped before the
  push: see "Branches of agents" below. A fresh session has only what is
  on `origin/main`. Check with `git log origin/main --oneline | head`.

## Batch 5 (issues #212 to #278, and the QA archive)

The triage files were in the scratchpad of the old session (lost). Each
fix commit names its issue number; use `git log --grep '#NNN'`.

Fixed on `main` (close each issue with the commit and a green CI run as
evidence; none is closed yet unless the issue says so):

* Packaging and docs: #211 (exclude list), #212, #213, #214 (except
  `share.rs` fetch_update if the share batch is not merged), #215, #216,
  #219, #220, #221, #223, #245, #246, #256, #257, #258. #222 and #224
  are steps of the stable release (`docs/maintenance.md`, Release).
* Update and install: #227, #236, #247, #270, #275.
* Group 6: #230, #248, #261 (fixed earlier in 35697cc), #268, #277,
  #278 (all five items), the #140 comment (`--l4` rules).
* Instances and CLI: #249, #251, #252 (with the `ssh-config --host`
  newline), #253, #254, #255, #260, #262, #263, #264, #265, #266, #267.
* Share, gate and config (merged at the end of the session if the push
  was done): #228, #229, #231, #232, #233, #234, #240, #241, #250, #269
  (items 1 and 2; a regex `path:` is a config error), #271, #276.

Not on `main` yet (parsers and egress branch, 13 commits, see below):
#225, #226, #235, #237, #238, #239, #242, #243, #244, #259, #272 (items
1 to 4, a part of 5), #273 (items 1, 3, 4), #274.

Still open, not started:

* #217: unit tests that fail or hang on a host that refuses
  `bind(AF_INET)` or has no loopback. Plan: a `#[cfg(test)]` probe
  (bind 127.0.0.1:0 once) and a skip macro in each such test; a CI job
  that runs the tests with bind refused.
* #218: `src/gate.rs` test asserts `is_none() || is_some()`. Make it
  assert the wrong code is refused.
* #273 item 2 (the 8 s limit for each leg attempt): a documented default;
  needs an owner decision before a change.
* #269 item 3 (a regex `path:` as in cloudflared): needs a decision on a
  `regex` dependency; now a regex-like `path:` is a config error.
* #276: the library `StaticServer` still holds a response in memory
  (capped at 64 MiB).
* #287 (QA, GitHub #307): `cfrs serve --local ADDR` (owner ruling: add
  it).
* #222, #224: at the stable release.

## The QA archive (findings #259 to #289)

* GitHub deleted #165 to #207 and #259 to #278 with the suspended account
  `aerrand-agent`. Their text is in `docs/reports/aerrand-agent.md`.
* All QA findings #259 to #289 are filed again on GitHub, by the owner
  account: GitHub number = QA number + 20 (QA #259 is GitHub #279, ...,
  QA #289 is GitHub #309). Each body names its QA number.
* Close at once, with evidence (owner ruling), the ones fixed on `main`:
  GitHub #281 (QA 261, 35697cc), #288 (268), #297 (277), #290 (270),
  #295 (275), #298 (278), and each of #280 to #287, #289, #291, #296
  whose fix is on `main` (see the list above with QA numbers).
* QA #279 to #289 (GitHub #299 to #309): an agent fixed them in a
  worktree branch (pod-netns seccomp, SOCKS5, inbound-dir, shim and
  switch sockets). Not on `main` if the branch was not picked.
* The recovered comments on #140, #217 and #252 are posted on those
  issues.

## Owner rulings of 2026-11-04 (in `docs/decisions.md`)

Releases unattended again; no crates.io publish and no package name; a
live check registers and deletes a WARP device through the second API
host; a MASQUE session through the relay is replaced before the relay
limit (done); `serve --local`; the seccomp backend intercepts `recvfrom`
and `recvmsg`; the shim and switch sockets take the same user only, and
the TCP switch needs a token; file each valid QA finding and close the
fixed ones.

## Branches of agents (local only; lost with the container)

If the session stopped before they were merged, their work is lost; redo
it from the issue texts:

* `worktree-agent-ae3285cfef1e21b24`: parsers and egress (13 commits,
  listed above). Merge with `git cherry-pick`, resolve, run
  `sh scripts/agent/check.sh`, push.
* `worktree-agent-a04ad45a9b2362a4f`: QA #279 to #289 (pod-netns and
  vnet). Was running.

To build in parallel worktrees: a private `CARGO_TARGET_DIR` for each
(cargo leaves the path of a local package out of its hash, so a shared
target mixes the test binaries), `CARGO_PROFILE_DEV_DEBUG=0`, and a short
`TMPDIR` such as `/tmp/cfrs-a1` (a long path breaks the unix socket
tests: 108 bytes).

## Next steps, in order

1. Merge what is left of the branches above (or redo it), with green
   checks.
2. Do #217, #218, #287 (`serve --local`).
3. Close each fixed issue on GitHub with its commit and the CI run.
4. Write `docs/releases/v0.3.0-beta.12.md`. Its `## Breaking` lists the
   lines "Breaking:" of the commit bodies since `v0.3.0-beta.11`
   (`git log v0.3.0-beta.11..main --grep Breaking`) and the batch 4 list
   in `docs/maintenance.md` "Open work".
5. Release `v0.3.0-beta.12` unattended (`docs/maintenance.md`, Release):
   dry run, `publish=v0.3.0-beta.12`, then `release-proofs.yml`.
6. Keep the issue watcher armed (`scripts/agent/watch-issues.sh`); it
   keeps a copy of each issue.
