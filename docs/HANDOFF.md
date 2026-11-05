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
* The newest release is `v0.3.0-beta.12` of cfrs. The first podnet
  release is T-023.
* The owner renames the GitHub repository `Azathothas/cfrs` to
  `Azathothas/podnet` after the session of 2026-11-05. GitHub then
  redirects the old URLs. Nobody may create a new `Azathothas/cfrs`: that
  ends the redirects.

## First steps of the next session, in order

1. Check the redirects and the remote (T-021):

   ```sh
   git remote get-url origin
   curl -sI https://github.com/Azathothas/cfrs | head -3
   curl -qfsS "https://forge.web.pkgforge.dev/github/repos/Azathothas/podnet?n=$RANDOM" | head -c 200
   ```

2. Read the CI runs of the head of `main`. Until the first podnet
   release, the live step of the update asserts that `podnet update`
   refuses `v0.3.0-beta.1` (the identity of the old repository). The
   install script and the README one-line install fail until the first
   podnet release exists.
3. Release `v0.4.0-beta.1` (`docs/maintenance.md`, Release; T-022,
   T-023). The note lists under `## Breaking` the whole
   rename: the binary, the crate paths, each `CFRS_*` variable (now
   `PODNET_*`), the state and run directories, the TUN name, the unit
   names, the shim names, `/__podnet/ws`, the asset names, the image, the
   dropped `pod-netns` binary. Users of cfrs install podnet fresh.
4. After the release: the owner makes the image
   `ghcr.io/azathothas/podnet` public if it is private (T-025); restore
   the positive update check in `live.yml` (T-024).
5. Arm the issue watcher (`scripts/agent/watch-issues.sh`). New issues
   become record entries (`CLAUDE.md`, "The plan").
6. Continue the work order of `TODO/PROGRESS.md`: M2 (file splits) next.
   The fixes of M5 can run in parallel.

## Facts for the next session

* The live job hit the WARP device limit (HTTP 429, error 1015) in run
  41987488063 at the nested session step. Each new live test that
  registers a device adds to this risk (T-101).
* `podnet pod` prints messages with the prefix `podnet-netns:`, and
  `podnet pod --version` prints `podnet-netns X` (T-135).
* The studies in `docs/research/podnet/` describe the code at 3bed023
  (before the rename). Their paths name the old layout.
