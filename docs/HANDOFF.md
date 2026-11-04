# Handoff

The state of the work of the session of 2026-11-04 (second session). Read
this file first, then `CLAUDE.md`, `docs/maintenance.md` and
`docs/decisions.md`. Delete this file when each item below is done.

## Where the code is

* `main` has all of batch 4, batch 5 and the QA findings #279 to #309.
  No agent branch is open. The newest release is `v0.3.0-beta.11`.
* A cloud session starts with a shallow clone (50 commits). Run
  `git fetch --unshallow origin main` before `git log v0.3.0-beta.11..main`.

## Next steps, in order

1. Check that `ci`, `live`, `deny` and `secrets` pass on the head of
   `main` (`scripts/agent/watch-runs.sh`).
2. Write `docs/releases/v0.3.0-beta.12.md` with each "Breaking:" line of
   `git log v0.3.0-beta.11..main --grep Breaking`. Set the version
   (`docs/maintenance.md`, Release).
3. Release `v0.3.0-beta.12`: dry run, `publish=v0.3.0-beta.12`, then
   `release-proofs.yml`.
4. Close each fixed issue with its commits, the CI run and the release:
   #212 to #258 except #222 and #224; #279 to #309; #310 (the live
   report) with the cause of each failure and the run that passed. The
   commits of GitHub #279 to #298 name the QA number (GitHub number
   minus 20); GitHub #281 (QA 261) is fixed by 35697cc.
5. Post a status comment on #89, #140, #149, #151, #161, #222 and #224,
   and keep them open (`docs/decisions.md`, "Deferred issues").
6. Keep the issue watcher armed (`scripts/agent/watch-issues.sh`).
