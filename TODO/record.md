This file holds the entries of milestone M0: the record, and the guards that each later commit
runs. A guard must exist before the renames, the splits and the crate extraction of M1 to M3
move code. `docs/research/podnet/architecture.md`, section 4.6, step A, gives the order. One
entry of M2 (T-015) is here, because it is a check of the record.

# T-008: A parity snapshot: the command tree, the public items and the test list, with a diff of two runs

**Source:** `docs/research/podnet/architecture.md`, section 4.6, step A1; the owner's ruling of
2026-11-05 on regressions (`docs/decisions.md`).
**Category:** chore
**Milestone:** M0
**Priority:** P1
**Effort:** S
**Status:** open

## Problem

M1 to M3 rename and move about 90,000 lines. No check shows that a command, a flag, a public
library item or a test is lost by a move. A lost item is a regression, and the owner forbids it.

## Premise

- `podnet man --json` prints the command tree with each flag (`src/manual/mod.rs`).
- `docs/research/podnet/parity-checklist.md` lists 63 commands, 316 own flags and arguments,
  1,127 public items and 1,004 tests, read at `3bed023`.
- `cargo test --workspace -- --list` prints the name of each test.
- No script in `scripts/agent/` records these facts.

## Approach

1. Write a script in `scripts/agent/` (parity-snapshot.sh). It writes three sorted files into a
   directory: the command paths and flags of `man --json`, the public items of `cargo doc` (the
   `all.html` page of each crate), and the test names of `cargo test --workspace -- --list`.
2. With a second directory as its argument, the script prints the diff. It exits 1 when an item
   is lost. A new item is not a fault.
3. Read a map file of `OLD NEW` lines, so that M1 can compare the `cfrs` names with the `podnet`
   names.
4. Write the use of the script in `docs/maintenance.md`, section "Tools".

## Prove

```sh
sh scripts/agent/parity-snapshot.sh /tmp/before
sh scripts/agent/parity-snapshot.sh /tmp/after /tmp/before   # exit 0: no item is lost
```

Plant: remove the flag `--run-for` of `tunnel`. The second run must exit 1 and name the flag.

# T-009: A size check: at most 800 lines in each source file, with an allowlist that can only shrink

**Source:** `docs/research/podnet/architecture.md`, sections 1.1 and 4.6, step A2;
`docs/research/podnet/podssh-copy.md`, section 2.8 (C12); the owner's ruling of 2026-11-05
(`docs/decisions.md`, File size).
**Category:** chore
**Milestone:** M0
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

32 files have more than 800 lines. `src/main.rs` has 7,103 lines. Nothing stops a file from
growing.

## Premise

- `docs/research/podnet/architecture.md`, section 1.1, lists the 32 files with their counts.
- podssh has the same check for 500 lines, with a floor of files read and `--plant-empty`
  (`Azathothas/podssh:scripts/check-repo.py`, check 1).
- `scripts/agent/check.sh` runs fmt, clippy and the tests. `.github/workflows/ci.yml` runs the
  same.

## Approach

1. Copy check 1 of podssh into a new script (scripts/check-size.py). Set the limit to 800. Read
   the roots `src`, `crates`, `tests`, `scripts`, `tools`, `shim` and `fuzz`.
2. Add an allowlist file with each file over 800 lines and its count now. A listed file fails
   when it grows. A listed file with fewer lines than its row fails until its row is lowered or
   removed. Thus the list can only shrink.
3. Keep the floor: a scan of fewer than 100 files fails. `--plant-empty` must fail.
4. Run the script in `scripts/agent/check.sh` and in `.github/workflows/ci.yml`.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, File size): a source file has at most 800 lines. A
script checks it in CI. The files that are larger now are in an allowlist and can only get
smaller.

## Prove

```sh
python3 -I scripts/check-size.py
python3 -I scripts/check-size.py --self-test
sh scripts/agent/check.sh
```

Plant: add a file of 801 lines in `src/`. The check must fail and name the file.

## Done

2026-11-05, commit 23aae7a (`check-size: 800 lines for each Rust file, with an allowlist that only
shrinks`). `scripts/check-size.py` and `scripts/size-allow.txt` (32 files over 800 lines);
`--self-test` plants each fault. CI runs it in the `workflows` and `plant` jobs;
`sh scripts/agent/check.sh` runs it: size 0.

# T-010: A layer check: no module refers to a module of a higher layer, with an allowlist of 18 references that can only shrink

**Source:** `docs/research/podnet/architecture.md`, sections 3.2, 3.3, 3.4 and 4.6, step A2.
**Category:** chore
**Milestone:** M0
**Priority:** P1
**Effort:** M
**Status:** open

## Problem

26 library modules of the root crate are one cycle of 47,671 lines. The crate split of M3 cannot
build while a lower module refers to a higher one. Nothing stops a new upward reference while M2
cuts the 18 that exist.

## Premise

- `docs/research/podnet/architecture.md`, section 3.3, lists the 18 upward references, each with
  the items that it uses.
- Section 3.2 gives the layer of each module: the core (process and files, network,
  supervisor), the adapters, the services, and the CLI with the diagnostics.
- The study read each `crate::X` of `src/` outside the test modules with its own tool, which is
  not in the repository.

## Approach

1. Write a script (scripts/check-layers.py) with the table of module to layer of section 3.2.
2. Read each file of `src/`. Drop the `#[cfg(test)]` modules. Find each `crate::MODULE`
   reference.
3. Fail on a reference from a lower layer to a higher one that is not in the allowlist. The
   allowlist has the 18 references of section 3.3. A listed reference that no longer exists
   fails until its row is removed.
4. Add `--plant-empty`. Run the script in `scripts/agent/check.sh` and in
   `.github/workflows/ci.yml`.

## Prove

```sh
python3 -I scripts/check-layers.py
python3 -I scripts/check-layers.py --plant-empty   # must exit 1
```

Plant: add `use crate::tunnel;` to `src/egress.rs`. The check must fail and name
`egress -> tunnel`.

# T-011: Loopback tests for the commands that have no behaviour test, before the splits

**Source:** `docs/research/podnet/architecture.md`, section 5 (the gaps);
`docs/research/podnet/parity-checklist.md`, section 14.
**Category:** chore
**Milestone:** M0
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Only the always-on pins (the command tree, the help lint, the manual) cover `bug-report`, `qr`,
`net demo`, `autostart run` and `agent status`. The pins show that a flag exists, not what it
does. A move of their code in M2 can break them, and no test fails.

## Premise

- `docs/research/podnet/parity-checklist.md`, section 14, lists these commands. It also lists
  `warp license`, `warp rotate` and `warp shell`, which need WARP: T-012 tests them.
- `tests/cli.rs` runs other commands of the binary on the loopback. `tests/detach.rs` tests
  `wait`.
- A test that binds TCP starts with `need_loopback!()` (`tests/test_host/mod.rs`).

## Approach

1. Add a test in `tests/cli.rs` for each command: `bug-report` (the report names the version
   and holds no secret of the environment), `qr` (the matrix of a known URL), `net demo` (it
   ends with exit 0), `autostart run` (it starts the recorded command), `agent status` (the JSON
   document when no agent runs).
2. Start each test that binds TCP with `need_loopback!()`.

## Prove

```sh
cargo test --test cli -- bug_report_names_the_version_and_no_secret qr_prints_the_matrix_of_a_url net_demo_ends_with_success autostart_run_starts_the_recorded_command agent_status_with_no_agent_is_a_document
```

Plant: return at the start of the arm of each command. Each new test must fail.

# T-012: WARP stand-ins on the loopback: the registration API and a MASQUE edge, with tests of the WARP commands

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.11, 3 (C3) and 5 (A3);
`docs/research/podnet/architecture.md`, section 5 (the commands with live steps only).
**Category:** chore
**Milestone:** M0
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

`warp register`, `warp status`, `warp license`, `warp rotate`, `warp delete`, `warp proxy`,
`warp forward`, `warp nc` and `warp shell` have live steps only, or no test. A move of
`src/warp/` in M2 and M3 is proven only by a run of `live.yml`. Each live run registers a
device, and the service limits the new devices of each address.

## Premise

- podssh has a fake edge (`Azathothas/podssh:crates/podssh-warp/src/stand_in.rs` and
  `inside.rs`): TLS 1.3 with a pinned key, connect-ip, a smoltcp stack inside, routes to
  loopback services, counters, a key change, and a "silenced" mode that takes the CONNECT and
  relays nothing. It has an API stand-in for `/reg`
  (`Azathothas/podssh:crates/podssh-warp/src/tests/api.rs`).
- podnet reads `PODNET_WARP_API` for the base of the API (`src/warp/register.rs`). The unit tests of
  podnet have only echo front doors (`src/warp/session.rs`).
- podssh uses smoltcp 0.14. podnet pins smoltcp 0.12 (`Cargo.toml`).

## Approach

1. Copy the API stand-in into a test module of `src/warp/`. Adapt it to the requests of
   `src/warp/register.rs`. Add loopback tests of `warp register`, `warp status`,
   `warp license`, `warp rotate` and `warp delete` with the API variable set to the stand-in.
2. Copy the edge stand-in. Adapt it to smoltcp 0.12, to the podnet `Identity` and to an override
   of the endpoint with a test root. Add loopback tests of `warp proxy` (a SOCKS5 client reaches
   a loopback HTTP server), `warp forward -L`, `warp nc` and `warp shell`.
3. Keep the "silenced" mode: the probe of T-068 uses it.
4. Keep both stand-ins out of each release build (`#[cfg(test)]`, or a feature that no release
   enables).

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Code of podssh): copy podssh code into podnet and
change it as necessary. The code of podssh needs no credit.

The owner, 2026-11-05 (`docs/decisions.md`, Shared crates): the shared crates of `PodUtils/podcrates` hold this code. podnet depends on the shared crate; it does not copy the code.

## Prove

```sh
cargo test --workspace -- warp_stand_in_
```

Each new test name starts with `warp_stand_in_`. Plant: a wrong pinned key in the edge stand-in.
The test of `warp proxy` must fail on the pin.

## Start condition

The shared crates exist in `PodUtils/podcrates` (T-137; the ruling "Order" of 2026-11-05 in `docs/decisions.md`).

# T-013: A daily check that the record's list of GitHub numbers agrees with GitHub

**Source:** `docs/research/podnet/podssh.md`, sections 1.8 and 1.10;
`docs/research/podnet/podssh-copy.md`, section 2.1 (C2); the owner's ruling of 2026-11-05
(`docs/decisions.md`, Plan tracking).
**Category:** chore
**Milestone:** M0
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

GitHub deleted issues of a suspended account before (the closed #165 to #207, and #259 to #278).
The record keeps the text of each issue. With no check, a new issue or pull request can stay out
of the record.

## Premise

- podssh has `Azathothas/podssh:scripts/check-github-numbers.py` and
  `Azathothas/podssh:.github/workflows/record-issues.yml`. Each day the job compares the list
  file of the record with `gh issue list` and `gh pr list`. A planted drop must fail.
- `scripts/agent/watch-issues.sh` and `scripts/agent/new-issues.py` poll for new issues. They
  write nothing into the record.
- The text of the deleted issues is in `docs/reports/aerrand-agent.md`.

## Approach

1. Copy the script and the workflow. Change the names.
2. Write the list file from `gh issue list --state all` and `gh pr list --state all`. Write
   `NUMBER issue deleted` for each deleted number.
3. Keep the step with `--plant-drop 1`. It must exit 1.
4. When the copy of the tool of the record already has this check, close this entry with that
   commit.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Plan tracking): GitHub issues are an inbox. Each
issue becomes entries, and the record keeps its text.

## Prove

```sh
python3 -I scripts/check-github-numbers.py
python3 -I scripts/check-github-numbers.py --plant-drop 1   # must exit 1
gh workflow run record-issues.yml
```

## Done

2026-11-05, commits 2474f28 and 1c41cf0. `scripts/check-github-numbers.py` and
`.github/workflows/record-issues.yml` (daily, 05:43 UTC). The check starts at #311; the 7 open
older issues are in `TODO/github.txt`. `--plant-drop 89` exits 1.

# T-014: The milestones M0 to M9 in a roadmap, and the open work of the maintenance page in the record

**Source:** `docs/research/podnet/podssh.md`, section 3 (Roadmap);
`docs/research/podnet/podssh-copy.md`, section 5 (A0b); `docs/maintenance.md`, section "Open
work"; `CLAUDE.md` (keep "Open work" current).
**Category:** docs
**Milestone:** M0
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`docs/maintenance.md` keeps the open work as bullets. The record holds the same work as entries
now. Two lists of one work go stale. No document gives the exit criterion of each milestone.

## Premise

- The section "Open work" of `docs/maintenance.md` has bullets for the pod seccomp backend, the
  datagram socket of the vnet shim, #217, `path:`, `pod doctor`, #206, #184, #172 item 3, #181
  item 6 and `try_update`. Each is an entry now: T-066, T-067, T-075, T-076, T-077, T-078,
  T-079, T-080, T-081 and T-132.
- `CLAUDE.md` tells each session to keep "Open work" current.
- The checker of podssh reads a roadmap page: it refuses an open checkbox there, and it checks
  that each entry listed under a milestone has that milestone.

## Approach

1. Write the roadmap (ROADMAP.md of the record directory): one section for each milestone M0 to M9, with its exit
   criterion and its entries by id. Write no checkbox.
2. Replace the work bullets of "Open work" in `docs/maintenance.md` with a pointer to the work
   order of the record and the ids of the entries.
3. Keep the facts that are not work (the shallow clone, the numbers of the QA archive) in
   `docs/maintenance.md`.
4. When the copy of the tool of the record already wrote these pages, close this entry with that
   commit.

## Prove

```sh
cargo todo check
cargo test --test docs
```

## Done

2026-11-05, the rename commit of 2026-11-05. `TODO/ROADMAP.md` has the milestones M0 to M9. The section
"Open work" of `docs/maintenance.md` names the record and keeps only facts. `cargo todo check`:
the record agrees.

# T-015: CI checks that each pushed commit moved the citations of the files that it changed

**Source:** `docs/research/podnet/podssh.md`, sections 1.8 and 1.10;
`docs/research/podnet/podssh-copy.md`, section 2.1.
**Category:** chore
**Milestone:** M2
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

A citation of a line names a place in a file. An edit of the file can leave the citation on
other code. podssh CI runs `cargo todo check --base HEAD~1` on each push. The CI of podnet does
not.

## Premise

- podssh has the step "the last commit left no citation unmoved", with `fetch-depth: 2`
  (`Azathothas/podssh:.github/workflows/build.yml`).
- The entries of podnet cite paths with no line while M2 splits the files
  (`docs/research/podnet/podssh-copy.md`, section 2.1).
- `.github/workflows/ci.yml` checks out with the default depth.

## Approach

1. Add a step to `.github/workflows/ci.yml`: `cargo todo check --base HEAD~1`, with
   `fetch-depth: 2`.
2. From then on, an entry can cite a line again.

## Prove

```sh
cargo todo check --base HEAD~1
```

Plant: edit a file that an entry cites at a line, in a commit that leaves the citation. The CI
step must fail.

## Start condition

T-045 is done: each file is under 800 lines, and the splits are over.
