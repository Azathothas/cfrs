# Handoff

The state at the end of the session of 2026-11-05 (the move and the take of
the shared crates). Read this file first, then `CLAUDE.md`,
`TODO/PROGRESS.md`, `docs/maintenance.md` and `docs/decisions.md`. Remove
this file when each step below is done.

## Where the code is

* The repository is `PodUtils/podnet`. GitHub redirects `Azathothas/cfrs`
  (T-021). Nobody may create a new `Azathothas/cfrs`: that ends the
  redirects.
* `crates/podnet-todo` is a wrapper of `pod-todo` v0.1.0 of
  `PodUtils/podcrates` (a git tag; T-137, partial).
* `.github/workflows/publish.yml` publishes to crates.io by trusted
  publishing. The switch `[workspace.metadata.podnet] crates-io` is false.
* The newest release is `v0.3.0-beta.12` of cfrs. No podnet release now.

## Next steps, in order

1. The podcrates session (`session_01DXe55yrKCQcv8EsqqHsc4u`) sends the
   patch for `pod-tls` when podcrates v0.2.0 is tagged. Apply it, run
   `sh scripts/agent/check.sh`, commit (T-137), push, and send it the
   commit of `main`. The patch moves the `rust-version` of the root,
   `podnet-netns` and `podnet-todo` to 1.99 and removes the plant step of
   the `msrv` job. Each toolchain pin must be 1.99.1 or newer: `ci.yml`,
   `live.yml`, `publish.yml`, `fuzz.yml`, `upstream.yml` (now 1.97.0), the
   image of `images/build`, and the Rust version in `README.md`.
2. Then `pod-proxy` (`src/egress.rs`, `src/proxy_auth.rs`, `src/fetch.rs`),
   `pod-dns` (`src/resolve.rs`) and `pod-ws` (`src/ws.rs`), each from its
   release.
3. Until podnet takes a crate, its source files in podnet change only for
   fixes; tell the podcrates session of each fix (`docs/decisions.md`,
   Who edits a shared crate). Frozen now: `tests/test_host/mod.rs`,
   `src/trust.rs`, `src/tls_fragment.rs`.
