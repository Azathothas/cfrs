This file holds the entries of milestone M1: the rename of `cfrs` to `podnet`, the crate
`podnet-netns` with no binary, and the first podnet release. `docs/research/podnet/rename.md`,
section 5, gives the steps and the hand edits. The owner ruled a clean break on 2026-11-05
(`docs/decisions.md`, Name, Rename and pod-netns). A commit that renames or moves a cited file
moves each citation of it in the record by hand.

# T-016: Rename `cfrs` to `podnet` in the code, the tests, the workflows, the scripts and the documents

**Source:** `docs/research/podnet/rename.md`, sections 1 and 5 (step 2, with the hand edits 1 to
6); the owner's rulings of 2026-11-05 (`docs/decisions.md`, Name and Rename).
**Category:** chore
**Milestone:** M1
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

The project is `podnet` now. The package, the binary, the library, 57 variables, the shims, the
state and run paths, the units, the metrics, the wire paths and the release assets carry the name
`cfrs`: 3,691 occurrences in 197 files.

## Premise

- `docs/research/podnet/rename.md`, section 1, lists each kind of place. A trial on a scratch
  copy passed fmt, clippy, the tests (but two tests that refuse a binary in `/tmp`),
  `scripts/check-workflows.py` and the fuzz build.
- The history keeps the old name: `docs/releases/`, `docs/reports/` and `tests/data/` (signed by
  the cfrs identity). The studies in `docs/research/` are readings at `3bed023`.
- A plain `cfrs` to `podnet` gives `podnetnet`. The shims need their own rule.

## Approach

1. Move the three files with the name in their path: images/cfrs to `images/podnet`,
   shim/cfrsnet.c to `shim/podnet-vnet.c`, shim/cfrssocks.c to `shim/podnet-socks.c`.
2. Run the ordered `sed` of `docs/research/podnet/rename.md`, section 5, step 2, on each tracked
   file but `docs/releases/`, `docs/reports/`, `docs/research/`, `tests/data/` and the lock files.
   It keeps `talaria0101/cfrs` and `nemo-010/cfrs`.
3. Write `Cargo.lock` and `fuzz/Cargo.lock` again with `cargo metadata`. No dependency version
   moves.
4. Do the hand edits that the tests need. In `src/update.rs`: `identity_in(repo, tag)` and
   `verify_bundle_for`, with the fixture of v0.3.0-beta.1 checked under the cfrs identity and
   refused under the podnet identity; the fixture asset name `cfrs-x86_64-unknown-linux-musl`.
   In `src/vnet/addr.rs`: the longest abstract name is 59 bytes. In `src/warp/up.rs`: the sorted
   list of the proxy variables.
5. Do the hand edits that no test catches, in `.github/workflows/live.yml`. The step "update to
   v0.3.0-beta.1" asserts the refusal "not https://github.com/Azathothas/podnet/" until T-024.
   The A/B step keeps the old asset URL of v0.3.0-beta.6 and `RUST_LOG=cfrs=debug` for the old
   binary.
6. Run `cargo fmt --all`. Move each citation of a moved file in the record.
7. Push the commit as the last push before the rename of the repository.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Name and Rename): the project is `podnet`. A clean
break: no `CFRS_*` aliases, no move of old state, no `cfrs` alias, no bridge release. The code
rename is the last push of the session of 2026-11-05. The shim names are the names of
`docs/research/podnet/rename.md`, section 5: podnet-vnet (`PODNET_VNET_*`) and podnet-socks
(`PODNET_SOCKS_*`).

## Prove

```sh
sh scripts/agent/check.sh
python3 -I scripts/check-workflows.py
cargo check --manifest-path fuzz/Cargo.toml --bins
sh -n scripts/install.sh
git grep -il cfrs -- . ':!docs/releases' ':!docs/reports' ':!docs/research' ':!tests/data' ':!*.lock'
```

The last command names only the files that keep the old name on purpose: the live A/B step, the
fixture test of `src/update.rs` and the facts of T-017. The CI run and the live run of the commit
pass.

## Start condition

T-008 is done (the parity snapshot).

## Done

2026-11-05, the rename commit of 2026-11-05 (`rename: cfrs is podnet`), made with a script that a trial
ran twice from a clean checkout with the same tree. `sh scripts/agent/check.sh`: fmt 0, clippy 0,
record 0, size 0, test 0. Rust 1.99 clippy, `scripts/check-workflows.py`, the fuzz build and
`sh -n scripts/install.sh` pass. The name grep lists only the files of the facts (README,
SECURITY, decisions, maintenance, CLAUDE), the update fixture of `src/update.rs` and the live
steps with the old assets. The parity snapshot is T-008.

# T-017: The documents and the scripts state the facts of the old name

**Source:** `docs/research/podnet/rename.md`, section 5 (step 2, hand edits 7, 8, 9 and 11;
step 3).
**Category:** docs
**Milestone:** M1
**Priority:** P2
**Effort:** S
**Status:** partial

## Problem

The `sed` of T-016 writes a false fact: "`podnet` is taken" on crates.io. The check of a release
up to v0.3.0-beta.12 needs the old identity and the old asset names. The package description
names only the tunnel. `scripts/rebuild.sh` cannot rebuild a cfrs tag after the rename.

## Premise

- `docs/decisions.md` and `docs/maintenance.md` state the crates.io facts. On 2026-11-05,
  `cfrs` is taken by another project, and `podnet` and `podnet-netns` are free.
- `README.md` and `SECURITY.md` show the cosign identity and the asset names.
- The `build.rs` of a cfrs tag reads `CFRS_BUILD_COMMIT`. `scripts/rebuild.sh` passes one name.

## Approach

1. Write the crates.io facts again: `cfrs` is taken, `podnet` is free.
2. In `README.md`, `SECURITY.md` and the head of the release notes, write that the releases up to
   v0.3.0-beta.12 are signed as
   `https://github.com/Azathothas/cfrs/.github/workflows/release.yml@refs/tags/TAG` and have
   `cfrs-TARGET` assets.
3. Write the new `description` and `keywords` of `Cargo.toml`: a network tool for restricted
   hosts, with the Cloudflare tunnel as one adapter.
4. In `scripts/rebuild.sh`, pass `CFRS_BUILD_COMMIT` and `PODNET_BUILD_COMMIT`, and take the name
   of the binary from the tag.
5. In the release steps of `docs/maintenance.md`, name the packages `podnet` and `podnet-netns`.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Rename and crates.io): a clean break, and no publish
on crates.io yet.

## Prove

```sh
cargo test --test docs
sh scripts/rebuild.sh v0.3.0-beta.12   # the rebuilt binary equals the published one
```

## Start condition

T-016 is done, or this entry goes into its commit.

# T-018: `CLAUDE.md` names `podnet`, its crates and the record

**Source:** `docs/research/podnet/rename.md`, section 5 (step 2, hand edit 10);
`docs/research/podnet/podssh.md`, section 3 (the router file).
**Category:** docs
**Milestone:** M1
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`CLAUDE.md` names the workspace `cfrs`, the crate `crates/podnet-netns`, the ruling on
`cfrs update` and an issue loop with no record. After the rename, each session reads stale
names.

## Premise

- `CLAUDE.md` is the owner's file. `docs/research/podnet/rename.md`, section 5, says: change it
  only on the owner's instruction.
- The rulings of 2026-11-05 are in `docs/decisions.md`.

## Approach

1. Write the change: the workspace `podnet` and its eight crates, `podnet update`, the record in
   `TODO/` with `cargo todo check` in the list of checks, and an issue loop that writes entries.
2. Show the diff to the owner. Commit it on the owner's instruction.

## Prove

```sh
cargo todo check
cargo test --test docs
```

## Done

2026-11-05, the rename commit of 2026-11-05. The owner asked for the change of the documents in the session
of 2026-11-05. `CLAUDE.md` names podnet, its crates, the size limit and the record. `cargo todo
check`: the record agrees.

# T-019: Drop the `pod-netns` binary, and move its integration tests to the root crate

**Source:** the owner's ruling of 2026-11-05 (`docs/decisions.md`, pod-netns);
`docs/research/podnet/rename.md`, section 5, step 4; `docs/research/podnet/parity-checklist.md`,
section 4.
**Category:** chore
**Milestone:** M1
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

The pod has two command lines: the `pod-netns` binary and `cfrs pod`. Both parse the same
arguments (`crates/podnet-netns/src/cli.rs`). Each release ships two binaries for each target.

## Premise

- The file src/main.rs of the crate pod-netns calls `main_with_args`. `cfrs pod` hands its arguments to the
  same function (`src/main.rs`).
- The test files seccomp.rs (30 tests), raw.rs and usage.rs of the crate pod-netns run the binary through `CARGO_BIN_EXE_pod-netns`.
- `.github/workflows/release.yml`, `.github/workflows/release-proofs.yml`,
  `scripts/install.sh`, `images/podnet/Dockerfile` and `tests/install_script.rs` name the binary
  and its assets.
- The library prints `cfrs pod` as its program name when cfrs calls it (`set_program_name` in
  `crates/podnet-netns/src/lib.rs`).

## Approach

1. Move the three test files to `tests/` of the root crate. Run the `pod` command of the root
   binary through its `CARGO_BIN_EXE_` variable. Keep each test name.
2. Remove the file src/main.rs of the crate pod-netns and the binary target of the crate. Keep the library and
   its unit tests.
3. Remove the `pod-netns` assets from the release, the proofs, the install script, its tests and
   the image. Name the removal in the `## Breaking` list of T-022.
4. Keep each option of the `pod-netns` command line under `pod`
   (`docs/research/podnet/parity-checklist.md`, section 4). Keep `pod doctor`.
5. Change `tests/docs.rs::pod_netns_ships_the_license` and the package list of
   `.github/workflows/ci.yml`.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, pod-netns): the crate is a library only. The
`pod-netns` binary is dropped. `podnet pod` is the only command line of the pod. Its integration
tests move to the root crate.

## Prove

```sh
cargo test -p podnet --test pod_seccomp --test pod_usage
cargo test -p podnet-netns --test raw
sh scripts/agent/check.sh
```

The count of tests does not go down. The parity diff names only the `pod-netns` binary.

## Start condition

T-008 is done (the parity snapshot).

## Done

2026-11-05, the rename commit of 2026-11-05. The binary target and its `main.rs` are gone. The tests moved to
`tests/pod_seccomp.rs` (30 tests) and `tests/pod_usage.rs` (3 tests); they run `podnet pod`.
No assertion changed. `crates/podnet-netns/tests/raw.rs` stays in the crate: it uses the library only. The release,
the proofs, the install script and the image do not ship the binary.

# T-020: Rename the crate `pod-netns` to `podnet-netns`

**Source:** the owner's rulings of 2026-11-05 (`docs/decisions.md`, pod-netns and Crates);
`docs/research/podnet/rename.md`, section 5, step 4.
**Category:** chore
**Milestone:** M1
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The core network crate keeps the old name in its directory, its package, its library path
`pod_netns` and two variables (`POD_NETNS_QUIET`, `POD_NETNS_TEST_MEM`).

## Premise

- `pod-netns` has 341 occurrences in 55 files, and `pod_netns` 85 in 20
  (`docs/research/podnet/rename.md`, section 5, step 4).
- The root crate uses the library in `src/main.rs`, `src/vnet/`, `src/warp/` and
  `src/manual/model.rs`.
- The tests of the manual scan `crates/podnet-netns/src` for variables (`src/manual/facts.rs`).

## Approach

1. Move `crates/podnet-netns` to crates/podnet-netns. Set the package name `podnet-netns` and the
   library name `podnet_netns`. Change the members of the workspace and the dependency of the
   root crate.
2. Rename `POD_NETNS_QUIET` to `PODNET_NETNS_QUIET` and `POD_NETNS_TEST_MEM` to
   `PODNET_NETNS_TEST_MEM`, with their rows of the manual.
3. Change the scan path of `src/manual/facts.rs`, the package list of `.github/workflows/ci.yml`
   and the `COPY` line of the image.
4. Move each citation of `crates/podnet-netns/` in the record in the same commit.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, pod-netns): the crate becomes `podnet-netns`, a
library only.

## Prove

```sh
sh scripts/agent/check.sh
cargo test -p podnet-netns
git grep -n -e pod-netns -e pod_netns -- . ':!docs/releases' ':!docs/reports' ':!docs/research' ':!TODO' ':!tests/data'
```

The last command prints nothing.

## Start condition

T-019 is done.

## Done

2026-11-05, the rename commit of 2026-11-05. The crate is `crates/podnet-netns`. The grep prints only the facts
of the old releases (README, decisions, maintenance).

# T-021: Verify the GitHub redirects after the repository rename

**Source:** `docs/research/podnet/rename.md`, sections 2 and 5, step 1.
**Category:** chore
**Milestone:** M1
**Priority:** P1
**Effort:** S
**Status:** blocked

## Problem

The binaries of cfrs, the old install line and old links name `Azathothas/cfrs`. GitHub
redirects a renamed repository until a new repository takes the old name. The update code
follows up to five HTTPS redirects (`src/update.rs`).

## Premise

- `docs/research/podnet/rename.md`, section 2: an installed v0.3.0-beta.12 reads the release list
  through the redirect and says "up to date" until a podnet release. After it, three checks
  refuse the podnet release: the asset name, the identity and the prefix of the version line.
- `Azathothas/podnet` was free on 2026-11-05.

## Approach

1. Set the remote: `git remote set-url origin https://github.com/Azathothas/podnet.git`.
2. Run the five `curl` commands of `docs/research/podnet/rename.md`, section 5, step 1. Write each
   status in the Done section.
3. Never create a new repository named `Azathothas/cfrs`: it stops each redirect.

## Prove

```sh
curl -sI https://github.com/Azathothas/cfrs | head -3
curl -sI "https://api.github.com/repos/Azathothas/cfrs/releases?per_page=1" | head -3
curl -sIL https://github.com/Azathothas/cfrs/releases/download/v0.3.0-beta.12/SHA256SUMS | grep -i '^HTTP'
curl -sI https://raw.githubusercontent.com/Azathothas/cfrs/main/scripts/install.sh | head -3
curl -qfsS "https://forge.web.pkgforge.dev/github/repos/Azathothas/podnet?n=$RANDOM" | head -c 200
```

Each of the first two prints a 301. The download ends in a 200.

## Blocker

The owner renames the repository `Azathothas/cfrs` to `Azathothas/podnet` on GitHub (Settings,
General, Repository name), after the push of T-016.

# T-022: The version `0.4.0-beta.1`, and its release note with each breaking change

**Source:** `docs/research/podnet/rename.md`, section 5, step 5; the owner's ruling of 2026-11-05
(`docs/decisions.md`, Rename).
**Category:** release
**Milestone:** M1
**Priority:** P1
**Effort:** S
**Status:** open

## Problem

The update code and the install script take the highest version of the release list, and the
renamed repository keeps the cfrs releases. So podnet must continue the version line above
v0.3.0-beta.12. Each rename breaks a user of cfrs, and the note must tell how to move.

## Premise

- `Cargo.toml` holds the version of the workspace and of the path dependency.
- `tests/docs.rs::each_tag_in_the_documents_has_a_release_note` scans only the tags that start
  with `v0.3.0-beta.`.
- A release note needs a `## Breaking` heading (`tests/docs.rs`, `.github/workflows/release.yml`).

## Approach

1. Set `0.4.0-beta.1` in `Cargo.toml`, `Cargo.lock` and `fuzz/Cargo.lock`.
2. Write the note in `docs/releases/` (v0.4.0-beta.1.md). Its `## Breaking` lists the binary, the
   crate `podnet-netns` with no binary, the assets, `podnet.1`, the image, the variables
   (`CFRS_X` is `PODNET_X`, `CFRSNET_X` is `PODNET_VNET_X`, `CFRSSOCKS_X` is `PODNET_SOCKS_X`),
   the state and run paths, `podnet0`, the units and the markers, the metrics, the paths
   `/__podnet/`, the User-Agent and the log filter `podnet=`.
3. Write the moves: install podnet fresh (`cfrs update` cannot install it); move
   `~/.local/state/cfrs` to keep the WARP device; run `cfrs autostart remove` and
   `cfrs warp down` first.
4. Extend the test of the tags to each `vX.Y.Z-beta.N`.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Rename): the first podnet release is `v0.4.0-beta.1`,
after the rename of the repository.

## Prove

```sh
cargo test --test docs
sh scripts/agent/check.sh
```

## Start condition

T-016, T-017, T-019 and T-020 are done.

# T-023: Publish `v0.4.0-beta.1`: the dry run, the publish and the release proofs

**Source:** `docs/research/podnet/rename.md`, section 5, step 5; `docs/maintenance.md`, section
"Release"; `CLAUDE.md` (Releases).
**Category:** release
**Milestone:** M1
**Priority:** P1
**Effort:** S
**Status:** open

## Problem

Between the code rename and the first podnet release, the install line of the README fails:
`scripts/install.sh` resolves the latest release to v0.3.0-beta.12, which has no podnet asset,
and the image `ghcr.io/azathothas/podnet:beta` does not exist.

## Premise

- `.github/workflows/release.yml` signs with the identity of `$GITHUB_REPOSITORY`. After the
  rename it is the identity of `Azathothas/podnet`, with no change of the workflow.
- `.github/workflows/release-proofs.yml` checks each file with cosign, runs
  `update --version TAG --force` on the published binary, and runs `scripts/rebuild.sh`.
- `scripts/release-short.sh` checks the prefix of the version line.

## Approach

1. Dispatch `release.yml` on `main` with `publish` empty: the dry run. Check the assets
   `podnet-TARGET`, `podnet.1` and `SHA256SUMS`, the version line `podnet 0.4.0-beta.1 (COMMIT)`
   and the build of the image.
2. Dispatch `release.yml` with `publish=v0.4.0-beta.1`.
3. Run `release-proofs.yml` on the tag. Run the install line of the README on a clean runner.

## Decision

The owner (`CLAUDE.md`, Releases): cut the next prerelease unattended when a batch is green: a
dry run, then `publish=vX`, then a check of `release-proofs.yml`.

## Prove

```sh
gh workflow run release.yml --ref main
gh workflow run release.yml --ref main -f publish=v0.4.0-beta.1
gh workflow run release-proofs.yml -f tag=v0.4.0-beta.1
curl -fsSL https://raw.githubusercontent.com/Azathothas/podnet/main/scripts/install.sh | sh
```

## Start condition

T-021 and T-022 are done.

# T-024: The update checks pass against a podnet release again

**Source:** `docs/research/podnet/rename.md`, section 5, step 6.
**Category:** chore
**Milestone:** M1
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

After T-016, the live update step asserts only the refusal of a cfrs release, and the unit tests
check only the bundle of a cfrs release. No check proves that `podnet update` installs a podnet
release.

## Premise

- `.github/workflows/live.yml` has the step "update to v0.3.0-beta.1", with `--rollback`.
- `tests/data/v0.3.0-beta.1.SHA256SUMS` and its bundle are the fixture of `src/update.rs`
  (`the_bundle_of_a_release`).

## Approach

1. In the live step, pin `v0.4.0-beta.1` again: the download, the signature, the install and
   `--rollback`.
2. Add the SHA256SUMS and the bundle of v0.4.0-beta.1 to `tests/data/`. Add a unit test of
   `verify_bundle` with the podnet identity on the default path.
3. Keep the test of the cfrs fixture through `identity_in("Azathothas/cfrs", ...)`.

## Prove

```sh
cargo test --workspace -- the_bundle_of_a_release the_bundle_of_a_podnet_release
gh workflow run live.yml
```

The live step "update to v0.4.0-beta.1" passes.

## Start condition

T-023 is done.

# T-025: The image `ghcr.io/azathothas/podnet` is public

**Source:** `docs/research/podnet/rename.md`, sections 4 and 5, step 7.
**Category:** chore
**Milestone:** M1
**Priority:** P2
**Effort:** S
**Status:** blocked

## Problem

A new package on ghcr can start as private. Then the anonymous pull of the README fails. The
token of a workflow cannot change the visibility of a package.

## Premise

- `ghcr.io/azathothas/cfrs` is public, with 46 tags. It stays after the rename.
- `.github/workflows/release.yml` pushes the image to `ghcr.io/OWNER/NAME`.

## Approach

1. After T-023, pull `ghcr.io/azathothas/podnet:beta` with no login.
2. When the pull fails, the owner sets the package to public (the settings of the package).
3. Optional: the owner writes "moved to ghcr.io/azathothas/podnet" in the description of the
   package `cfrs`.

## Prove

```sh
docker logout ghcr.io
docker pull ghcr.io/azathothas/podnet:beta
```

## Blocker

The owner sets the visibility of the package `podnet` on ghcr to public, after the first podnet
release (T-023). Only the owner can change it.

## Start condition

T-023 is done.
