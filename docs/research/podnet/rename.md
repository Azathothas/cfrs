# Rename `cfrs` to `podnet`: viability and exact steps

Study of 2026-11-05, on `main` at 3bed023 (`/workspace/cfrs`). Read only. The
counts come from `git ls-files | xargs grep` (no `target/`).

Scope rule from the owner (correction during the study): "no regression"
means no loss of a feature or a capability in the code. It does not mean
compatibility for existing users. A clean break is acceptable. This report
therefore recommends **no compatibility layer**, and it gives the exact,
complete rename steps.

## 0. Verdict

* The rename is viable and mostly mechanical: 3,691 occurrences of the name
  (any case) in 197 files, after the history files are excluded.
* A trial on a scratch copy (`git archive HEAD`) proved the method:
  one ordered `sed`, three `git mv`, a regeneration of the two lock files,
  four test edits and `cargo fmt --all`. Result:
  * `cargo check --workspace --all-targets`: ok.
  * `cargo clippy --workspace --all-targets -- -D warnings`: ok.
  * `cargo fmt --all --check`: ok after `cargo fmt --all` (33 hunks reflow,
    because `podnet` is 2 characters longer than `cfrs`).
  * `cargo test --workspace`: all pass, except 2 tests of `tests/cli.rs`
    (`autostart_with_cron_and_with_nothing`,
    `autostart_from_an_instance_keeps_its_secrets_and_drops_detach_options`).
    They fail only because the trial built under `/tmp`: `src/autostart.rs:408`
    refuses a binary in `/tmp`. They do not fail in `/workspace`.
  * `python3 -I scripts/check-workflows.py`: 8 files, 0 faults.
  * `cargo check --manifest-path fuzz/Cargo.toml --bins`: ok.
  * `sh -n scripts/install.sh`: ok.
  * Diff: 197 files, +3,553 / −3,461 lines.
  * The scripts: `rename-tools/rename.sh`, `rename-tools/handfix.py`, and the
    full diff `rename-tools/trial.diff`, all under
    `(scratch copy, not kept)`.
* No release can cross from `cfrs` to `podnet` with the update code of
  beta.12 (three independent checks block it, see section 2). A bridge
  release costs a full release cycle in this session. Its value is small,
  because the state directory, the variables, the units and the paths change
  anyway. Recommendation: a clean break, with "install podnet fresh" in the
  release note.

## 1. Inventory: each kind of place where the name occurs

Kept unchanged (history, or signed data): `docs/releases/v0.3.0-beta.*.md`
(313 occurrences, 12 files), `docs/reports/aerrand-agent.md` (414),
`tests/data/v0.3.0-beta.1.SHA256SUMS` and `.sigstore.json` (4; signed by
the cfrs identity, so they cannot change).

In scope: 3,691 occurrences in 197 files. By area (lines that contain the
name / files):

| Area | Lines | Files |
| --- | --- | --- |
| `src/`, `crates/*/src`, `shim/`, `build.rs`, `examples/`, `fuzz/`, manifests | 1,926 | 131 |
| `tests/`, `crates/*/tests` | 425 | 20 |
| `.github/` | 250 | 6 |
| `scripts/`, `tools/`, `images/`, `notebooks/` | 205 | 25 |
| Documents (`README.md` 394 occ., `SECURITY.md` 51, `docs/protocol.md` 60, `docs/target-environment.md` 39, `docs/virtual-network.md` 38, `docs/maintenance.md` 19, `docs/decisions.md` 10, `docs/development.md` 5, `crates/pod-netns/README.md` 4, `CLAUDE.md` 4, `about.*`, `cliff.toml`, `THIRD_PARTY_NOTICES.md`) | 550 | 14 |

`src/main.rs` alone: 805 lines of 7,103.

By kind (occurrences / files, in scope):

| Kind | Where | Count |
| --- | --- | --- |
| Package, lib and bin name | `Cargo.toml` (`[package] name`, `[lib] name`, `[[bin]] name`, `repository`, `homepage`, `description`), `crates/pod-netns/Cargo.toml` (`repository`, `homepage`), `fuzz/Cargo.toml` (`cfrs-fuzz`, dependency `cfrs = { path = ".." }`), `Cargo.lock`, `fuzz/Cargo.lock` | 6 + 2 + 3 + lock files |
| `cfrs::` paths | `src/main.rs` 414, `tests/` 29, `fuzz/` 18 targets, `examples/` 4, docs | 492 / 41 |
| `CARGO_BIN_EXE_cfrs` | `tests/cli.rs` 43, 8 other test files | 55 / 9 |
| CLI name | `src/main.rs:49` `#[command(name = "cfrs")]` (gives `--version` = `cfrs X (commit)`; checked: clap prints this name also when argv[0] differs), `src/main.rs:2552` completions name, `src/manual/roff.rs:79,132` `.TH`, `src/manual/text.rs:207` | — |
| Environment variables `CFRS_*` | 57 distinct names, 514 occ. / 66 files. `src/manual/facts.rs` lists 47 of them, plus 13 `CFRSNET_*`/`CFRSSOCKS_*`. Not in facts: `CFRS_VERSION`, `CFRS_INSTALL_DIR`, `CFRS_POD_NETNS`, `CFRS_REPO` (also read by `src/update.rs:506`), `CFRS_NO_VERIFY`, `CFRS_DOWNLOADER` (all `scripts/install.sh`), `CFRS_BUILD_COMMIT`/`_TARGET`/`_DATE` (build), `CFRS_BIN`, `CFRS_KEEP` (README cell, notebook), `CFRS_WARP_SOCKET` (written into env files by `src/warp/up.rs`) | 514 / 66 |
| Shim names | `shim/cfrsnet.c`, `shim/cfrssocks.c`, `libcfrsnet.so`, `libcfrssocks.so` (`src/vnet/shim.rs:14-26`, `include_str!`), abstract prefix `cfrsnet` (`src/vnet/addr.rs:25`), `CFRSNET_*` (8 names), `CFRSSOCKS_*` (5), `/tmp/cfrsnet.socks`, `/tmp/cfrssocks.sock`, `cfrsnet.switch` | 113 + 61 / 20 |
| State, config and run directories | `src/state.rs:41-62` (`$XDG_STATE_HOME/cfrs`, `~/.local/state/cfrs`, `$XDG_RUNTIME_DIR/cfrs`, `cfrs-<uid>`), `src/instances.rs:35-84` (`CFRS_RUN_DIR`, `$XDG_RUNTIME_DIR/cfrs/run`, sockets such as `warp.sock`), `src/relay.rs:74-77` (`cfrs-relay`, `cfrs-origin-<uid>.sock`), `cfrs-ca.pem` beside the binary, `~/Downloads/cfrs`, `~/cfrs-uploads` (`src/main.rs:3436`) | 36 / 13 (paths) |
| TUN name | `src/main.rs:4496` default `cfrs0`; tests in `src/warp/route.rs`, `src/warp/up.rs` | 33 / 8 |
| Units and markers | `src/autostart.rs:358,456,589` `cfrs-<name>.service`, cron marker `# cfrs autostart <name>`; `src/warp/up.rs:26-27` `# >>> cfrs warp up >>>`, `:514` env.d mark, `90-cfrs-warp.conf`, `conf.d/cfrs-warp.fish` | — |
| Process titles | `src/detach.rs:505,884` `arg0("cfrs")`, `:1058` `PR_SET_NAME "cfrs"` | 3 |
| JSON | No `schema` value holds the name (all are the integer 1: `src/report.rs:368`, `src/status.rs:123`, `src/warp/mod.rs:434`). One value: `"target": "cfrs"` in the JSON error line (`src/main.rs:1517`) | 1 |
| Log filter (tracing target = crate name) | `src/main.rs:1011-1016` default `cfrs=info/debug/trace/warn`; `RUST_LOG=cfrs=…` in `live.yml` (5), `scripts/` (4), `tests/` (3), `docs/maintenance.md`, `src/manual/facts.rs:243` | 20 / 10 |
| Metrics | `src/metrics.rs` `cfrs_*_total`, `cfrs_active_streams` | 30 / 3 |
| Wire-visible strings | User-Agent `cfrs/{v}` (`src/config.rs:297`, `src/fetch.rs:246`), `cfrs/{v} (rust)` (`src/quicktunnel.rs:228`, trycloudflare), `User-Agent: cfrs` (`src/warp/exit.rs:197`); `Basic realm="cfrs"` (`src/proxy.rs:147`, `src/warp/proxy.rs:712`); SSH user `cfrs` to `free.pinggy.io` (`src/relay.rs:63`); paths `/__cfrs/ws` (`src/ws.rs:32`), `/__cfrs/unlock` (`src/gate.rs:18`) | 24 / 12 for `__cfrs` |
| Repository URL | `src/update.rs:27` `REPOSITORY`, `crates/pod-netns/src/doctor.rs:335`, `src/manual/text.rs:243`, `scripts/install.sh`, `scripts/rebuild.sh`, `scripts/agent/*.sh`, `cliff.toml:22`, `live.yml:832`, README (22), docs | 53 / 17 |
| Release assets | `cfrs-<target>` (`release.yml` lines 104-361, `release-proofs.yml` 71-168, `ci.yml` 167-183 artifact names, `scripts/install.sh`, `scripts/rebuild.sh`, `src/update.rs:80,519`), `cfrs.1` (`release.yml:134,352`, `release-proofs.yml:76-77`, `ci.yml:71-75`) | 40 + 14 |
| Image | `images/cfrs/Dockerfile` (12: `/var/lib/cfrs`, `CFRS_STATE_DIR`, entry point), `release.yml:458-527` (`ghcr.io/<owner>/cfrs`), README | — |
| CI specifics | `ci.yml:59-64` (`cargo package --list -p cfrs`, `pkg-cfrs.txt`, `shim/cfrsnet.c`), `ci.yml:131` (MSRV `-p cfrs --lib`), `release.yml:447` (`--title "cfrs $TAG"`), `release.yml:35` and scripts (`CFRS_BUILD_COMMIT`) | — |
| Tests that assert the name | `tests/cli.rs` (233 occ.), `tests/install_script.rs` (48), `tests/egress.rs` (31), `tests/connect.rs` (26), `tests/shim_direct.rs` (15), `tests/signals.rs` (14), `tests/detach.rs` (11), and the unit tests of `src/update.rs`, `src/manual/mod.rs:171,224` (`CFRS(1)`, `.TH CFRS 1`), `src/autostart.rs`, `src/warp/up.rs`, `src/warp/route.rs`, `src/vnet/addr.rs:516` | 436 / 21 |

Files with the name in the path (3): `images/cfrs/Dockerfile`,
`shim/cfrsnet.c`, `shim/cfrssocks.c`.

## 2. The self-update chain

### What beta.12 has compiled in (`src/update.rs`)

| Item | Value | Line |
| --- | --- | --- |
| Repository | `Azathothas/cfrs` | 27 |
| Release list | `https://api.github.com/repos/{REPOSITORY}/releases?per_page=30` | 150 |
| Fallback list | `https://github.com/{REPOSITORY}/releases.atom` | 241 |
| Pinned download | `https://github.com/{REPOSITORY}/releases/download/{tag}/{name}` | 71 |
| Asset | `cfrs-{asset_target(TARGET)}` | 80, 519 |
| Certificate identity | `https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/{tag}`, issuer `https://token.actions.githubusercontent.com` | 96-98, 29 |
| Trial of the new binary | first line of `--version` starts with `cfrs {version} ` | 743 |
| Trial of a rollback | starts with `cfrs ` | 775 |
| Redirects | `get()` follows up to 5 HTTPS redirects (301, 302, 303, 307, 308) | 118-145 |

`scripts/install.sh`: `repo=${CFRS_REPO:-Azathothas/cfrs}`, assets
`$name-$target` for `cfrs` (and `pod-netns`), version check
`"cfrs ${tag#v}"` (line 117), cosign identity
`https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag`.

`release.yml` and `release-proofs.yml` take the identity from
`$GITHUB_REPOSITORY`. After the rename, a new release is signed as
`https://github.com/Azathothas/podnet/.github/workflows/release.yml@refs/tags/…`
with no change to the workflows.

### What happens to an installed beta.12 after the rename

GitHub redirects a renamed repository (web, git, API with 301,
`releases/download`, `releases.atom`) until a new repository takes the old
name. `get()` follows these redirects. Verify with `curl -sI` after the
rename (section 5, step 1); `raw.githubusercontent.com` is expected to
redirect too.

1. Before the first podnet release: `cfrs update` reads the list through the
   redirect, finds v0.3.0-beta.12, and says "up to date".
   `cfrs update --version v0.3.0-beta.N` keeps working (the old assets and
   signatures stay in the renamed repository).
2. After the first podnet release (for example v0.4.0-beta.1, assets
   `podnet-<target>`):
   * API path: `release.asset("cfrs-x86_64-unknown-linux-musl")` fails:
     "the release v0.4.0-beta.1 has no file cfrs-x86_64-unknown-linux-musl".
   * Atom path (API 403): the pinned URLs download SHA256SUMS and the
     bundle, and `verify_bundle` refuses: "the certificate names
     [https://github.com/Azathothas/podnet/…], not
     https://github.com/Azathothas/cfrs/…".
   * The binary does not change in either path. `cfrs update --check` says
     that v0.4.0-beta.1 is available (it does not download), which is
     misleading but harmless.
3. Three independent checks block the move: the asset name, the identity and
   the trial prefix `cfrs X `. A `cfrs-<target>` copy in podnet releases
   does not help, because the identity check still fails. Only a release
   signed by the `Azathothas/cfrs` workflow can pass, and that is possible
   only before the rename.

### A bridge release: design, cost, verdict

A last release from the cfrs repository before the rename (v0.3.0-beta.13)
would have to:

* choose by tag: for a tag above v0.3.0-beta.13, the identity
  `…/Azathothas/podnet/…`, the asset `podnet-<target>` and the trial prefix
  `podnet {v} `; else the cfrs values. A rollback accepts both prefixes.
* keep `REPOSITORY = "Azathothas/cfrs"` for the URLs (it works before the
  rename and through the redirect after it).

podnet would have to keep its version above v0.3.0-beta.13. Cost: about
40 lines and 3 unit tests in `src/update.rs`, and a full release cycle in
this session (ci, live, dry run, publish, release-proofs). Only one fix
landed since beta.12 (3bed023).

Value: one command saves one download. But `update` writes the new binary
in place of `current_exe`, so the file stays named `cfrs`. All
`CFRS_*` variables, the state directory (the WARP identity), the units, the
TUN name and the socket paths change anyway. A tester must redo the setup.
**Verdict: not worth it.** Use a clean break and one line in the release
note: "cfrs is now podnet; `cfrs update` cannot install it; install podnet
fresh with the one-liner."

Optional, not recommended: a "tombstone" v0.3.0-beta.13 whose `update`
prints "cfrs is now podnet; install it with …" when the newest release has
no `cfrs-<target>` asset (about 15 lines). It also needs a full release
cycle before the rename.

### What podnet must do

* `REPOSITORY = "Azathothas/podnet"`, asset `podnet-<target>`, trial
  `podnet {v} ` (all from the mechanical rename).
* Continue the version line above v0.3.0-beta.12: **v0.4.0-beta.1**. The
  old releases stay in the list of the renamed repository. `choose()` and
  `install.sh highest()` take the highest version. A podnet v0.1.0 would
  make `podnet update` pick v0.3.0-beta.12 (and then fail on the asset).
* No runtime acceptance of the cfrs identity. The unit test of the real
  bundle of v0.3.0-beta.1 stays useful: give `verify_bundle` the identity as
  a parameter (`identity_in(repo, tag)`, `verify_bundle_for(…, want)`), test
  the fixture with `identity_in("Azathothas/cfrs", …)`, and add one
  assertion that the podnet identity refuses it (done in the trial,
  `handfix.py`). Optional (about 25 lines): a by-tag table that also
  accepts the cfrs identity, asset and prefix for tags up to v0.3.0-beta.12.
  It keeps `podnet update --version v0.3.0-beta.12` (a downgrade to cfrs)
  and the live step against v0.3.0-beta.1. Not needed for a clean break.

### Before the rename (this session) and after it

Before (this session):

1. Required: nothing in the code. `Azathothas/podnet` is free (section 4),
   which the GitHub rename needs.
2. Do not push the code rename before the repository rename. Reasons: the
   live step `update --check` would read
   `api.github.com/repos/Azathothas/podnet` (404 until the rename); the
   README one-liner and `install.sh` would point at a missing repository;
   a release made before the rename gets the cfrs identity, which podnet
   refuses.
3. Recommended: add the ruling to `docs/decisions.md` (rename, v0.4.0-beta.1,
   clean break, supersede the crates.io ruling "`cfrs` is taken"), write
   `docs/HANDOFF.md` with section 5 of this report, and update "Open work" in
   `docs/maintenance.md`. `tests/docs.rs::each_path_in_the_documents_exists`
   checks the paths in backticks in `docs/decisions.md` and
   `docs/maintenance.md`: do not write future paths (for example
   `shim/podnet-vnet.c`) in backticks there.
4. Optional, not recommended: a final or tombstone v0.3.0-beta.13 (the last
   chance to sign with the cfrs identity).
5. The owner renames the repository (Settings, General, Repository name).
   Never create a new repository named `Azathothas/cfrs` after that: it
   stops every redirect (old links, the old install one-liner, the old
   binaries' `update --version`).

After (the fresh session in `Azathothas/podnet`): section 5.

## 3. Compatibility layer

Recommendation: none. Per item:

| Item | Recommendation |
| --- | --- |
| `CFRS_*` read as fallback for `PODNET_*` | Drop. The release note lists the rename rule (`CFRS_X` is `PODNET_X`; `CFRSNET_X` is `PODNET_VNET_X`; `CFRSSOCKS_X` is `PODNET_SOCKS_X`). |
| State directory migration or fallback | Drop the code. Add one release-note line: move `~/.local/state/cfrs` to `~/.local/state/podnet` (or set `PODNET_STATE_DIR`) to keep the WARP device. Reason: the ruling "do not register WARP devices when it is not necessary". |
| `cfrs` argv[0] alias, symlink, second `[[bin]]` | Drop. clap ignores argv[0] for parsing, and `--version` prints the command name. |
| TUN `cfrs0` | Rename to `podnet0` (7 bytes, under IFNAMSIZ). |
| Units, cron marker, `warp up` markers and files | Rename. Release note: run `cfrs autostart remove NAME` and `cfrs warp down` before the switch, because podnet does not see the cfrs markers. Optional (about 10 lines): `podnet warp down` also removes the cfrs block and files. |
| JSON keys | Nothing to keep: no `schema` holds the name. The JSON error line value `"target"` changes to `podnet`. |
| Metrics `cfrs_*` | Rename to `podnet_*`. |
| `/__cfrs/ws`, `/__cfrs/unlock` | Rename to `/__podnet/…`. Client and server must both be podnet. |
| SECURITY/README: the verification of old releases | Keep (documents only, clearly useful): releases up to v0.3.0-beta.12 are signed with `https://github.com/Azathothas/cfrs/.github/workflows/release.yml@refs/tags/<tag>` and have `cfrs-<target>` assets. |
| `scripts/rebuild.sh` for old tags | Optional (about 6 lines): pass both `-e CFRS_BUILD_COMMIT` and `-e PODNET_BUILD_COMMIT`, and take the binary name from the tag (`cfrs` or `podnet`). Without it, `rebuild.sh v0.3.0-beta.12` from main fails (the old `build.rs` reads `CFRS_BUILD_COMMIT`, so the rebuilt binary prints `unknown` and differs). The rebuild of new tags works without it. |

## 4. Names: crates.io, GitHub, ghcr (checked 2026-11-05)

| Name | Result |
| --- | --- |
| crates.io `podnet` | 404: free |
| crates.io `podnet-netns`, `podnet-core`, `podnet-cloudflare`, `podnet-cli`, `podnet-tunnel` | 404: free (crates.io treats `-` and `_` as the same) |
| crates.io `pod-netns`, `pod-net` | 404: free |
| crates.io `cfrs` | 200: taken (another owner, 4 versions, 2024) |
| GitHub `Azathothas/podnet` | 404: free (the rename needs this) |
| GitHub `Azathothas/cfrs` | 200, id 1440651801 |
| GitHub org `Podnet` | exists (thepodnet.com, 23 public repositories, since 2019): no conflict, but the name overlaps in search |
| ghcr `ghcr.io/azathothas/podnet` | anonymous token refused: no public package (free in the owner's namespace) |
| ghcr `ghcr.io/azathothas/cfrs` | public, 46 tags (v0.3.0-beta.8 to beta.12, `:beta`); it stays after the rename |

Nothing is reserved. The ruling "publish nothing now" stands until the owner
decides (question 4).

A new ghcr package can start as private. After the first podnet release,
check an anonymous pull of `ghcr.io/azathothas/podnet:beta`. If it fails, the
owner sets the package to public (package settings); the workflow token
cannot do it.

## 5. Ordered steps (commits), size and guards

### Step 1 (after the rename, no commit): verify the redirects

```sh
git remote set-url origin https://github.com/Azathothas/podnet.git
curl -sI https://github.com/Azathothas/cfrs | head -3                       # 301
curl -sI "https://api.github.com/repos/Azathothas/cfrs/releases?per_page=1" | head -3   # 301
curl -sIL https://github.com/Azathothas/cfrs/releases/download/v0.3.0-beta.12/SHA256SUMS | grep -i '^HTTP'
curl -sI https://raw.githubusercontent.com/Azathothas/cfrs/main/scripts/install.sh | head -3
curl -qfsS "https://forge.web.pkgforge.dev/github/repos/Azathothas/podnet?n=$RANDOM" | head -c 200
```

### Step 2 (one commit): the new name in the code, the tests, the workflows, the scripts and the documents

Size: 197 files, about 3,460 lines changed (+3,553 / −3,461 in the trial, with
the fmt reflow), 3 moves. It must be one commit: the bin name, the tests,
`ci.yml`, `live.yml` and `release.yml` depend on each other, and each pushed
commit must be green.

Commands (the repository form of the trial):

```sh
git mv images/cfrs images/podnet
git mv shim/cfrsnet.c shim/podnet-vnet.c
git mv shim/cfrssocks.c shim/podnet-socks.c
git ls-files -z | grep -zv -e '^docs/releases/' -e '^docs/reports/' -e '^tests/data/' -e '\.lock$' |
  xargs -0 grep -lZ -i cfrs | xargs -0 sed -i \
    -e 's/CFRSNET_/PODNET_VNET_/g' -e 's/CFRSSOCKS_/PODNET_SOCKS_/g' \
    -e 's/cfrsnet/podnet-vnet/g' -e 's/cfrssocks/podnet-socks/g' \
    -e 's#talaria0101/cfrs#talaria0101/@KEEP@#g' -e 's#nemo-010/cfrs#nemo-010/@KEEP@#g' \
    -e 's/CFRS/PODNET/g' -e 's/Cfrs/Podnet/g' -e 's/cfrs/podnet/g' -e 's/@KEEP@/cfrs/g'
cargo metadata --format-version 1 > /dev/null                                 # Cargo.lock
cargo metadata --format-version 1 --manifest-path fuzz/Cargo.toml > /dev/null # fuzz/Cargo.lock
python3 -I handfix.py      # the 4 test edits below
cargo fmt --all
sh scripts/agent/check.sh
```

The lock regeneration changes only the `cfrs` (and `cfrs-fuzz`) entries to
`podnet` (and `podnet-fuzz`); no dependency version moves (checked).

Hand edits that the tests need (in `handfix.py`, about 30 lines):

1. `src/update.rs`: `identity_in(repo, tag)` and
   `verify_bundle_for(bundle, sums, want)`; the fixture test
   `the_bundle_of_a_release` uses `identity_in("Azathothas/cfrs", …)` and
   asserts that the podnet identity refuses the fixture.
2. `src/update.rs`: `a_line_of_sha256sums` looks up
   `cfrs-x86_64-unknown-linux-musl` (the name in the fixture).
3. `src/vnet/addr.rs:516`: the longest abstract name is 59 bytes
   (`podnet-vnet/6/` is 14 bytes), not 55. The limit is 107.
4. `src/warp/up.rs:867`: the sorted list is
   `["ALL_PROXY", "HTTPS_PROXY", "PODNET_PROXY"]`.

Hand edits that no `cargo test` catches (same commit):

5. `.github/workflows/live.yml:294-314` (step "update to v0.3.0-beta.1"):
   until the first podnet release, assert the refusal:
   `podnet update --version v0.3.0-beta.1` must fail with
   "not https://github.com/Azathothas/podnet/" (this proves the download,
   the Fulcio chain and the identity check). Keep `update --check`. Keep the
   rollback check with two local copies.
6. `.github/workflows/live.yml:831-844` (A/B with beta.6): the URL must keep
   the old asset name
   `…/releases/download/v0.3.0-beta.6/cfrs-x86_64-unknown-linux-musl`. Run
   the old binary with `RUST_LOG=cfrs=debug` (its tracing target is `cfrs`).
   Without this edit the download fails silently (`|| old=""`) and the A/B
   comparison stops.
7. `docs/decisions.md:27`, `docs/maintenance.md:140,235`: the sed writes
   "`podnet` is taken". Write the facts: `cfrs` is taken; `podnet` is free.
8. `README.md:69-70`, `SECURITY.md`, `docs/releases` head template: add the
   old identity and asset names for releases up to v0.3.0-beta.12.
9. `Cargo.toml` `description` and `keywords`: the new scope (owner text).
10. `CLAUDE.md` (4 occurrences: workspace name, `cfrs update` ruling): only
    with the owner's instruction.
11. Optional: `scripts/rebuild.sh` for old tags (section 3).

Name decisions inside the sed (owner can change them before the run):
`cfrsnet` becomes `podnet-vnet` (`libpodnet-vnet.so`, `PODNET_VNET_*`,
abstract prefix `podnet-vnet/…`, `/tmp/podnet-vnet.socks`);
`cfrssocks` becomes `podnet-socks` (`libpodnet-socks.so`, `PODNET_SOCKS_*`,
`/tmp/podnet-socks.sock`); `CFRSBOX` becomes `PODNETBOX`. The plain sed
`cfrs`→`podnet` would give `podnetnet` and `PODNETNET_*`.

Guards of step 2:

* `cargo test --workspace`: `src/manual/facts.rs`
  `each_variable_in_the_source_is_in_the_manual` and
  `each_variable_in_the_manual_is_read_by_the_source` (each renamed
  variable, both directions); `src/manual/mod.rs` (`PODNET(1)`,
  `.TH PODNET 1`); `src/update.rs` tests; `tests/cli.rs` (help, version,
  outputs, examples of the manual parse); `tests/docs.rs` (paths in the
  documents exist, notebook cell = README cell, the `--detach` sentence,
  tags have notes); `tests/install_script.rs` (asset names, version line,
  atom fallback); `tests/api_surface.rs` (the library paths `podnet::`);
  `tests/shim_direct.rs`, `tests/shim_socks.rs` (the embedded C shims and
  their variables); `crates/pod-netns/tests`.
* `cargo clippy … -D warnings`, `cargo fmt --all --check`.
* `scripts/check-workflows.py`; `cargo check --manifest-path fuzz/Cargo.toml`
  (or dispatch `fuzz.yml`).
* CI `ci.yml`: the package list (`pkg-podnet.txt`, `shim/podnet-vnet.c`),
  the man page lint (`podnet.1`), MSRV `-p podnet --lib`, the static builds
  and artifacts `podnet-<target>`.
* `live.yml`: the real edge with the new User-Agent and `/__podnet/ws`;
  the update refusal step. The SSH relay user `podnet` on `free.pinggy.io`
  has no live step: try it once by hand.
* `release.yml` dry run: assets `podnet-*`, `podnet.1`, `SHA256SUMS`, the
  version line `podnet X (commit)`, `scripts/release-short.sh` (prefix
  `podnet `), the image build from `images/podnet/Dockerfile`.
* `secrets.yml`: no allowlisted line of `.github/secrets-allow.txt` holds the
  name (12 lines checked), so the commit adds no finding. Only the comment of
  `tests/cli.rs:1449` changes.

### Step 3 (one commit): rulings and maintenance documents

`docs/decisions.md` (the rename ruling; the crates.io ruling superseded: the
name is `podnet`), `docs/maintenance.md` ("Open work"; the release steps name
the packages `podnet` and `pod-netns` in both lock files), remove
`docs/HANDOFF.md` when it is done. About 40 lines, 3 to 4 files. Guard:
`tests/docs.rs`.

### Step 4 (optional, one commit, same breaking release): `pod-netns` to `podnet-netns`

`git mv crates/pod-netns crates/podnet-netns`; workspace `members`,
dependency path and name; `[lib] name = "podnet_netns"`; the bin name;
assets `podnet-netns-<target>`; `PODNET_POD_NETNS` → `PODNET_NETNS`
(install.sh); `POD_NETNS_QUIET` (6), `POD_NETNS_TEST_MEM` (9); the image
`COPY`. Size: `pod-netns` 341 occurrences / 55 files, `pod_netns` 85 / 20
(about 400 lines). Guards: as step 2, plus
`crates/pod-netns/tests/seccomp.rs` (23 `CARGO_BIN_EXE_pod-netns`),
`usage.rs`, `tests/docs.rs::pod_netns_ships_the_license`, the `ci.yml`
package list.

### Step 5 (one commit, then the release): v0.4.0-beta.1

Do it in the same session as step 2. Between step 2 and the publish, the
README one-liner fails: `install.sh` resolves `latest` to v0.3.0-beta.12,
which has no `podnet-<target>` ("no podnet-x86_64-unknown-linux-musl in
v0.3.0-beta.12"), and `ghcr.io/azathothas/podnet:beta` does not exist.

* Version `0.3.0-beta.12` → `0.4.0-beta.1`: `Cargo.toml` (workspace and the
  `pod-netns` dependency), `Cargo.lock`, `fuzz/Cargo.lock`.
* `docs/releases/v0.4.0-beta.1.md`: `## Breaking` lists each rename (binary,
  crate, assets, `podnet.1`, image, `PODNET_*` and the shim prefixes, state
  and run directories, `podnet0`, `podnet-<name>.service` and the markers,
  metrics, `/__podnet/…`, User-Agent, the log filter `podnet=…`), and "install
  podnet fresh; `cfrs update` cannot install podnet; move
  `~/.local/state/cfrs` to keep the WARP device; run `cfrs autostart remove`
  and `cfrs warp down` first".
* `tests/docs.rs::each_tag_in_the_documents_has_a_release_note`: it scans
  only `v0.3.0-beta.`; extend it to each `vX.Y.Z-beta.N`, else a v0.4.0 tag in
  the README is not checked.
* About 150 lines, 5 files. Guards: `tests/docs.rs` (the Breaking heading),
  the dry run of `release.yml`, then `publish=v0.4.0-beta.1`, then
  `release-proofs.yml` (each file, cosign 3.1.4 and 2.6.5 with the identity
  `…/Azathothas/podnet/…`, `podnet update --version v0.4.0-beta.1 --force` on
  the published binary, `scripts/rebuild.sh`).

### Step 6 (one commit, after the release): positive update checks again

* `live.yml`: the update step pins v0.4.0-beta.1 again (download, signature,
  install, `--rollback`).
* `tests/data/v0.4.0-beta.1.SHA256SUMS` and `.sigstore.json`, and a unit test
  with the podnet identity (`verify_bundle`, the default path). Keep the cfrs
  fixture test through `identity_in("Azathothas/cfrs", …)`.
* About 40 lines, 3 files plus 2 data files. Guards: `cargo test`, `live.yml`.

### Step 7 (owner, no commit)

Check an anonymous pull of `ghcr.io/azathothas/podnet:beta`; set the package
public if needed. Optional: write "moved to ghcr.io/azathothas/podnet" in
the description of the `cfrs` package.

## 6. Open questions for the owner

1. The shim names: `podnet-vnet` / `PODNET_VNET_*` and `podnet-socks` /
   `PODNET_SOCKS_*` (proposed), or other names. Blocks step 2.
2. `pod-netns` to `podnet-netns` in the same breaking release (step 4), or
   later with the module split. Blocks step 4.
3. The version line: v0.4.0-beta.1 (it must be above v0.3.0-beta.12).
   Blocks step 5.
4. Reserve `podnet` (and `podnet-netns`) on crates.io now with a first
   publish, or keep "publish nothing" (ruling of 2026-11-04).
5. A final or tombstone v0.3.0-beta.13 before the rename: recommended no.
6. The GitHub organisation `Podnet` (thepodnet.com) exists: is the overlap
   acceptable?
7. The text of the new `description` and `keywords` in `Cargo.toml`.
