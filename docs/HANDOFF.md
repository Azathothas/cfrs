# Handoff

The state at the end of the session of 2026-11-05 (the move and the take of
the shared crates). Read this file first, then `CLAUDE.md`,
`TODO/PROGRESS.md`, `docs/maintenance.md` and `docs/decisions.md`. Remove
this file when each step below is done.

## Where the code is

* The repository is `PodUtils/podnet`. GitHub redirects `Azathothas/cfrs`
  (T-021). Nobody may create a new `Azathothas/cfrs`: that ends the
  redirects.
* podnet takes `pod-todo`, `pod-core`, `pod-tls` and `pod-proxy` of
  `PodUtils/podcrates` by the git tag `v0.3.0` (T-137, partial). The
  toolchain is Rust 1.99.1.
* `.github/workflows/publish.yml` publishes to crates.io by trusted
  publishing. The switch `[workspace.metadata.podnet] crates-io` is false.
* The newest release is `v0.3.0-beta.12` of cfrs. No podnet release now.

## Next steps, in order

1. The podcrates session (`session_01DXe55yrKCQcv8EsqqHsc4u`) sends the
   patch of each next crate on the day of its release: `pod-dns`
   (`src/resolve.rs`), `pod-ws` (`src/ws.rs`), `pod-services`. Apply it
   (`git apply --3way`), run `cargo todo remap Cargo.lock`,
   `cargo update -w` in `fuzz/`, `sh scripts/agent/check.sh` and
   `cargo deny --locked check`, commit (T-137), push, and send it the
   commit of `main`. A raise of `rust-version` must also hold for each
   toolchain of `release.yml`: run a release dry run.
2. Until podnet takes a crate, its source files in podnet change only for
   fixes; tell the podcrates session of each fix (`docs/decisions.md`,
   Who edits a shared crate). Frozen now: `tests/test_host/mod.rs`;
   `src/resolve.rs` with its tests (`pod-dns`, from 380d9a4); each place of
   `docs/reports/services-inventory-2026-11-05.md` (`pod-services`).
3. `pod-services` (`docs/decisions.md`, Services crate): the lists of
   services of other parties, their measurements and the watch workflows
   move to podcrates. Add no new hardcoded service. The inventory for the
   podcrates session is `docs/reports/services-inventory-2026-11-05.md`;
   podcrates imports from `main` and sends a patch.
4. The pin `smoltcp = "=0.12.0"` of `Cargo.toml` names Rust 1.91 as its
   reason. That reason is gone at Rust 1.99; the move to smoltcp 0.14 is
   wave 2 of T-137 (`pod-netstack`).
