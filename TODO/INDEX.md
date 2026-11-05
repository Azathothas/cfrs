# Index

Each entry of the work record, one row each, sorted by id. The entry is in
the area file that its row links. It closes there, with its Prove run and
the result written.

`TODO/PROGRESS.md` has the only work order. `TODO/RULES.md` gives the rules
of the record. `TODO/issues.md` maps each GitHub issue to its entries.

`cargo todo set` and `cargo todo counts` derive the counts from the rows.
`cargo todo check` makes sure that the counts, the rows and the entries
agree.

## Values

**Priority.**

- **P0**: correctness fails, data is lost, or the process stops.
- **P1**: a documented capability does not work, or a flag does nothing.
- **P2**: worth doing; nothing is wrong without it.
- **P3**: worth recording, so that nobody must find it again.

**Effort.** S is less than one day. M is some days. L is one week. There
is no XL: make two entries.

**Status.** `open`, `partial`, `blocked` or `done` (`TODO/RULES.md`).

**Milestone.** `M0` to `M9`, as in `TODO/ROADMAP.md`: M0 Record, M1
Rename, M2 Split, M3 Crates, M4 Adapters, M5 Fixes, M6 Services, M7 Pods,
M8 Overlays, M9 Later.

**Category.** `defect`, `feature`, `measurement`, `release`, `chore`,
`research` or `docs`.

## Entries

**7 entries: 0 open, 0 partial, 7 blocked, 0 done.**

| Priority | open | partial | blocked | done | total |
| --- | --- | --- | --- | --- | --- |
| P0 | 0 | 0 | 0 | 0 | 0 |
| P1 | 0 | 0 | 0 | 0 | 0 |
| P2 | 0 | 0 | 5 | 0 | 5 |
| P3 | 0 | 0 | 2 | 0 | 2 |
| **All** | 0 | 0 | 7 | 0 | 7 |

| ID | Priority | Effort | Milestone | Category | Status | Item |
| --- | --- | --- | --- | --- | --- | --- |
| [T-001](deferred.md) | P3 | S | M9 | chore | blocked | Tracking: dev work in a sandbox with basic networking, and launch once and forget (GitHub #89) |
| [T-002](deferred.md) | P2 | M | M9 | feature | blocked | `warp proxy --l4`: the L4 door answers 403 to each form of the CONNECT (GitHub #140) |
| [T-003](deferred.md) | P2 | S | M9 | feature | blocked | `warp register`: enrol through a Zero Trust team token (GitHub #149) |
| [T-004](deferred.md) | P3 | M | M9 | feature | blocked | TLS: send an encrypted ClientHello on the hops that publish a config (GitHub #151) |
| [T-005](deferred.md) | P2 | S | M9 | release | blocked | crates.io: publish the library and the CLI (GitHub #161) |
| [T-006](deferred.md) | P2 | S | M9 | release | blocked | crates.io: the workspace version and the `pod-netns` requirement are prereleases (GitHub #222) |
| [T-007](deferred.md) | P2 | S | M9 | release | blocked | crates.io: the name `cfrs` belongs to another project; choose a package name (GitHub #224) |
