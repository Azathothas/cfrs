# Progress

`TODO/INDEX.md` holds 138 entries: 119 open, 1 partial, 7 blocked, 11 done.

## State

- The repository is `PodUtils/podnet`; GitHub redirects `Azathothas/cfrs` (T-021).
- The ruling "Order" of 2026-11-05 (`docs/decisions.md`): only the move and the take of the
  shared crates go on now (T-137). There is no release now. Each other entry waits until podnet
  takes the shared crates.
- podnet takes each crate of `PodUtils/podcrates` by a git tag, on the day of its release (T-137).
  Done: `pod-todo` v0.1.0, `pod-tls` and `pod-core` v0.2.0. Next: `pod-proxy`, `pod-dns`,
  `pod-ws`.
- Keep this section short. Write the current state only; git keeps the history.

## Work order

1. **Now:** T-137: take each crate of `PodUtils/podcrates` from its release, with the patch of
   the podcrates session. T-025 waits for the first release (T-023).
2. **Hold:** each other entry waits until podnet takes the shared crates (T-137). Then write the
   new order here (T-137, step 4). The order below is the order before the hold; T-137 changes
   it.

### The order before the hold

Finish each entry, close it in place, change this page in the same commit, then take the next
one. In a milestone: P1, then P2, then P3. At one priority, an S entry goes first when it does
not wait for a larger one.

1. **M0, the record and the guards:** T-008, T-010, then T-011 and T-012.
2. **M1, the rename:** T-022, T-023 and T-024, then T-025. They wait for the ruling "Order": no
   release now.
3. **M5, the fixes, at any time from M0, beside M1 to M4:** T-070, T-063, T-068, T-064, T-069;
   then T-072, T-075, T-077, T-081, T-071, T-073, T-066, T-067, T-074; then T-065, T-076, T-078,
   T-079, T-080. A fix in a pod backend lands before T-040 starts, or after it ends.
4. **M2, the splits:** T-026; T-027, then T-028 to T-031, then T-032; T-033 to T-041; T-042,
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
10. **M9, later:** T-119 to T-130, T-132, T-133 and T-134, each when its start condition holds.
    T-123, T-124, T-126, T-127, T-128 and T-129 take `pod-ts`, `pod-egress`, `pod-derp` and
    `pod-acme` (wave 4). T-131 closes with the take of `pod-session`, `pod-e2e` and `pod-identity`.

Cut the next prerelease (`v0.4.0-beta.N`) unattended when a batch is green (`CLAUDE.md`).

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
