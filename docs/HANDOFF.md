# Handoff

The state at the end of the session of 2026-11-05. Read this file first,
then `CLAUDE.md`, `TODO/PROGRESS.md`, `docs/maintenance.md` and
`docs/decisions.md`. Remove this file when each step below is done.

## Where the code is

* `main` has the rename cfrs -> podnet (one commit; `docs/decisions.md`,
  2026-11-05): the crates `podnet` and `podnet-netns` (a library; the
  `pod-netns` binary is gone, `podnet pod` is the CLI), the record tool
  `podnet-todo`, the record `TODO/` (entries T-001 to T-135) and the size
  check `scripts/check-size.py`.
* The newest release is `v0.3.0-beta.12` of cfrs. No podnet release is
  planned before the shared crates exist (T-023 waits).
* The owner transfers the GitHub repository `Azathothas/cfrs` to the
  organization `PodUtils` and renames it `podnet` after the session of
  2026-11-05. GitHub then redirects the old URLs. Nobody may create a new `Azathothas/cfrs`: that
  ends the redirects.

## First steps of the next session, in order

1. Check the redirects and the remote (T-021):

   ```sh
   git remote get-url origin
   curl -sI https://github.com/Azathothas/cfrs | head -3
   curl -qfsS "https://forge.web.pkgforge.dev/github/repos/PodUtils/podnet?n=$RANDOM" | head -c 200
   ```

2. Read the CI runs of the head of `main` (T-136). Before the move, each
   step that reads `PodUtils/podnet` fails with HTTP 404 (live run
   41994001349: `podnet update` could not read the release list). After
   the move, the live step of the update must pass: `podnet update`
   refuses `v0.3.0-beta.1` for its identity. Close GitHub #311 with the
   failed runs, their causes and the run that passed.
3. Arm the issue watcher (`scripts/agent/watch-issues.sh`). New issues
   become record entries (`CLAUDE.md`, "The plan").
4. Hold. The ruling "Order" of 2026-11-05: no release `v0.4.0-beta.1`
   now, and each other entry waits until the shared crates exist in
   `PodUtils/podcrates` (T-137). The work on the shared crates happens in
   that repository. When they exist, do T-137: depend on them, move the
   WARP and Cloudflare adapters (T-050, T-052), and write the new order in
   `TODO/PROGRESS.md`.

## Facts for the next session

* The live job hit the WARP device limit (HTTP 429, error 1015) in run
  41987488063 at the nested session step. Each new live test that
  registers a device adds to this risk (T-101).
* `podnet pod` prints messages with the prefix `podnet-netns:`, and
  `podnet pod --version` prints `podnet-netns X` (T-135).
* The studies in `docs/research/podnet/` describe the code at 3bed023
  (before the rename). Their paths name the old layout.
