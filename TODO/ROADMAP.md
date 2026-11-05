# Roadmap

The milestones of the work record, in order. Open work is an entry in
`TODO/`: this page names entries by id, under the milestone of their row,
and has no open checkbox. `cargo todo check` refuses an id under another
milestone, and a `- [ ]` item. Write the exit criteria of a milestone in
full with its first entries.

## M0: Record

The work record exists, and CI checks it on each push. Each open GitHub
issue and each item of "Open work" in `docs/maintenance.md` is an entry.

## M1: Rename

The package, the binaries, the library, the variables, the documents and
the workflows have the name podnet.

## M2: Split

No Rust file has more than 800 lines: `scripts/size-allow.txt`, the
allowlist of `scripts/check-size.py`, is empty.

## M3: Crates

The library is in crates by layer, with no edge from a lower crate to a
higher crate.

## M4: Adapters

Each network is an adapter behind the network and service traits. The
Cloudflare tunnel is one adapter.

## M5: Fixes

Each open defect of the field and lab reports has its fix and its test.

## M6: Services

The router, the file server, the file transfer and the git hosting.

## M7: Pods

The pod backends (`podnet pod`, the crate of `crates/pod-netns`).

## M8: Overlays

The overlay networks (Tailscale and others) as adapters.

## M9: Later

Deferred work. Each entry waits for the owner or for a condition outside
the repository.

- T-001, T-002, T-003, T-004, T-005, T-006, T-007: the deferred GitHub
  issues (`docs/decisions.md`, "Deferred issues").
