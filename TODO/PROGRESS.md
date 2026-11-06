# Progress

`TODO/INDEX.md` holds 141 entries: 92 open, 1 partial, 7 blocked, 41 done.

## State

- The repository is `PodUtils/podnet`; GitHub redirects `Azathothas/cfrs` (T-021).
- The ruling "Order" of 2026-11-06 (`docs/decisions.md`): the work on podnet's own code goes on,
  beside the take of the shared crates (T-137). There is no release now.
- podnet takes `pod-todo`, `pod-core`, `pod-tls`, `pod-proxy`, `pod-dns` and `pod-services`
  (`PodUtils/podcrates` v0.6.0). Next: `pod-ws` (`src/ws.rs`). A session reads the state
  of podcrates with `sh scripts/agent/podcrates.sh` (`docs/maintenance.md`, Shared crates).
- Keep this section short. Write the current state only; git keeps the history.

## Work order

1. **At each release of podcrates:** T-137, the take of each crate whose hand-off
   `adoption/podnet/CRATE.patch` is at the tag (`docs/maintenance.md`, Shared crates). It goes
   before other work.
2. **podnet's own work:** the order below. Skip an entry whose Correction says that its work is
   the take of a crate of podcrates: it waits for the release of that crate. An entry that changes
   frozen code (`sh scripts/agent/podcrates.sh`) waits for the take, except a fix. Add no new
   hardcoded host or service of another party (`docs/decisions.md`, Services crate).
3. **Waits for the owner:** the releases T-022, T-023, T-024 and T-025 (no release now).

### The order of podnet's own work

Finish each entry, close it in place, change this page in the same commit, then take the next
one. In a milestone: P1, then P2, then P3. At one priority, an S entry goes first when it does
not wait for a larger one.

1. **M0, the record and the guards:** T-012.
2. **M1, the rename:** T-022, T-023 and T-024, then T-025, when the owner allows releases
   again.
3. **M5, the fixes, at any time from M0, beside M1 to M4:** each
   entry of this list is done. A fix in a pod backend lands before T-040 starts, or after it ends.
4. **M2, the splits:** T-030 and T-031, then T-032; T-033 to T-041; T-042,
   T-043, T-044; T-045; then T-015.
5. **M3, the crates:** T-046, T-047, T-048, T-051, T-053, then the prerelease T-054. T-049, T-050
   and T-052 are the takes of `pod-relay`, `pod-warp` and `pod-cloudflare` of `PodUtils/podcrates`
   (T-137): do not do them in podnet.
6. **M4, the adapters:** T-055, T-056, T-057, T-058, T-059, T-060, T-061, T-062.
7. **M6, the services:** the shared parts T-082, T-083, T-084, T-085, T-086 (a take of
   `pod-session`, `pod-e2e` and `pod-identity`), T-087; the file
   server T-088, T-089, T-090, T-091; git T-092, T-093, T-094; the router T-095, T-096, T-097,
   T-098, T-099, T-100, T-101; the transfer T-102 and T-103 (takes of `pod-wormhole` and `pod-transit`), T-104, T-105, T-106.
8. **M7, the pods:** T-107, T-108, T-111, T-109, T-110, T-113, T-112.
9. **M8, the overlays:** T-114, T-115, T-116, T-117, T-118.
10. **M9, later:** T-119 to T-130, T-132 and T-134, each when its start condition holds.
    T-123, T-124, T-126, T-127, T-128 and T-129 take `pod-ts`, `pod-egress`, `pod-derp` and
    `pod-acme` (wave 4). T-131 closes with the take of `pod-session`, `pod-e2e` and `pod-identity`.

When the owner allows releases again: cut the next prerelease (`v0.4.0-beta.N`) unattended when
a batch is green (`CLAUDE.md`).

## Parked entries

These entries stay open. The condition in each entry tells when it can start.

| Entry | Start condition |
| --- | --- |
| T-131 | T-137 takes `pod-session`, `pod-e2e` and `pod-identity` (the owner chose the source: a git tag) |
| T-132 | The ruling "Order" ends (`try_update` is stable at the `rust-version` 1.99) |

## Calls made without a ruling

Each call is in its entry, and the work goes on with it until the owner rules otherwise:

- T-016: the shim names `podnet-vnet` (`PODNET_VNET_*`) and `podnet-socks` (`PODNET_SOCKS_*`).
- T-046: the test helpers go into `podnet-core` behind a feature; `pod-testkit` of
  `PodUtils/podcrates` is read first.
- T-065: the handoff of an upstream descriptor for Unix-socket upstreams only.
- T-068: podnet renews a WARP session by itself after three failed TCP probes to 1.1.1.1:443.
- T-070: a pointer file of `warp up` in the runtime directory of the user, outside the state
  directory.
- T-087: the resumable layer alone first; the end-to-end channel as an option.
- T-100: the config file of the router in YAML, read by the reader of the tree.
- T-103: an inflate decoder for the zip of a directory (own code or a pure Rust crate), in the
  shared crate that reads the zip.
- T-112: `--host-gateway` off by default.
- T-126 to T-130: the extra egress roads, the DERP carrier, ACME, iroh and a relay of podnet's
  own have no ruling; each asks the owner before its work starts.

## Owner actions

| Entry | Action |
| --- | --- |
| T-007 | Reserve the crate names `podnet-core`, `podnet-netns`, `podnet-vnet` and `podnet-serve` (0.0.0 placeholders, as `podnet`) |

## Questions for the owner

None now.

Write each question as `- **Qn.** QUESTION`, with the entries
that it blocks and a recommendation. Number the questions in sequence
from Q1.
