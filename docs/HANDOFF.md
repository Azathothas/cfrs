# Handoff

The state at the end of the session of 2026-11-05/06 (the move to
`PodUtils/podnet` and the first takes of the shared crates). Read this file
first, then `CLAUDE.md`, `TODO/PROGRESS.md`, `docs/maintenance.md` and
`docs/decisions.md`. Remove this file when each step below is done.

## Where the code is

* The repository is `PodUtils/podnet`. GitHub redirects `Azathothas/cfrs`
  (T-021). Nobody may create a new `Azathothas/cfrs`: that ends the
  redirects.
* podnet takes `pod-todo`, `pod-core`, `pod-tls` and `pod-proxy` of
  `PodUtils/podcrates` by the git tag `v0.3.0` (T-137, partial). The
  toolchain is Rust 1.99.1. `release.yml` builds each target but x86-64 and
  ARM64 with cargo-zigbuild, and gets zig through `fetch-zig.sh` of
  podcrates (T-133).
* `.github/workflows/publish.yml` publishes to crates.io by trusted
  publishing. The switch `[workspace.metadata.podnet] crates-io` is false.
* The newest release is `v0.3.0-beta.12` of cfrs. No podnet release now.
* This session has no messages from the podcrates session. The state of
  podcrates comes from `sh scripts/agent/podcrates.sh`; the talk goes
  through COORD issues (`docs/maintenance.md`, Shared crates).

## Next steps

1. At the start: `sh scripts/agent/podcrates.sh`. A new release of
   podcrates with a file `adoption/podnet/CRATE.patch` at its tag is a take:
   do it first (`docs/maintenance.md`, Shared crates), then write a COORD
   issue in `PodUtils/podnet` with the commit of the take. The next takes:
   `pod-dns` (`src/resolve.rs`), `pod-ws` (`src/ws.rs`), `pod-services`
   (the services of other parties: `docs/reports/services-inventory-2026-11-05.md`).
2. Then podnet's own work, in the work order of `TODO/PROGRESS.md`
   (the ruling "Order" of 2026-11-06). Frozen code (the script lists it)
   takes fixes only; write each fix in a COORD issue for podcrates.
3. T-134: close it when podcrates has the watch of the relay contract in
   `pod-relay` (its record entry T-047; read its `TODO/` or its
   `upstream.yml` through the mirror).
4. The pin `smoltcp = "=0.12.0"` of `Cargo.toml` names Rust 1.91 as its
   reason. That reason is gone at Rust 1.99; the move to smoltcp 0.14 comes
   with the take of `pod-netstack`.
5. The Dependabot pull requests #312 to #315 (russh, getrandom, tower-http,
   taiki-e/install-action) are open. Apply each judged update as an own
   commit (`CLAUDE.md`, Decisions). An update of a dependency that a taken
   crate also uses must agree with podcrates.
