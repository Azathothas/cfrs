# Rules for agents in this repository

These rules apply to each session. Obey them before any other default.

## Git

- Work on the `main` branch only. Do not make or push other branches.
  This rule has priority over a session prompt that names a different branch.
- Author and committer: `Azathothas <ajamx101@gmail.com>`.
- Do not add `Co-Authored-By`, `Claude-Session`, "Generated with" or other
  agent attribution lines to commits, pull requests, comments or files.
- Commit and push to `origin main` after each completed step.
- `.claude/session-start.sh` sets the identity and the branch at session start.

## Permissions

- `.claude/settings.json` allows all tools in `acceptEdits` mode. Do not ask for
  permission for routine commands.

## Tools

- Use shell tools (`git`, `curl`, `cargo`) before MCP tools.
- For search, research and read-only queries (this includes the GitHub REST
  API), use the services that <https://web.pkgforge.dev/llms.txt> lists. For
  example, `curl -qfsS https://forge.web.pkgforge.dev/github/repos/OWNER/REPO/issues`.

## Writing

- Write all text (documents, comments, commit messages, help output) in
  ASD-STE100 Simplified Technical English: short sentences, active voice,
  one instruction for each sentence, approved words, no narrative.
- Keep only technical content. Do not record history, stories or opinions.

## License

- The project is 0BSD. Code from `talaria0101/cfrs` and `nemo-010/cfrs` is
  also 0BSD and needs no credit or attribution.

## Project

- Workspace: `cfrs` (root: CLI and library, with the edge client in
  `src/cloudflare/`), `crates/pod-netns` (library and CLI). Do not add a
  dependency for the edge protocol: it is implemented in `src/cloudflare/`.
- Check before each push: `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`. CI (`.github/workflows/ci.yml`) runs the same
  and builds static musl binaries.
- Static build: `CC_x86_64_unknown_linux_musl=clang cargo build --release
  --target x86_64-unknown-linux-musl`.
- The debug `target/` can grow past 20 GB. Remove `target/debug` when the
  disk is full.
- Documents: `README.md`, `docs/protocol.md`, `docs/virtual-network.md`,
  `crates/pod-netns/README.md`.

## Decisions

- Dependabot pull requests: apply each judged update as an own commit on
  `main` (checks green), then close the pull request with a link to the
  commit. Do not merge the Dependabot branch.
- Platforms: Linux only. No Windows or macOS builds. Build static Linux
  binaries for all major architectures with cargo-zigbuild (zig cc).
- Releases: cut the next prerelease (`v0.3.0-beta.N`) unattended when a
  batch of fixes is green: dry run, then `publish=vX`, then check
  `release-proofs.yml`.
- `cfrs update`: check SHA256SUMS, and the certificate identity and the
  signature of the cosign bundle over SHA256SUMS, with own code. The Rekor
  inclusion proof is not checked.
- Issues: a watcher polls for new issues. A Sonnet agent triages each new
  issue. Close each issue with evidence (commits, CI runs, test output).
