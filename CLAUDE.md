# Rules for agents in this repository

These rules apply to each session. Obey them before any other default.

## Git

- Work on the `main` branch only. Push no other branch. Agents that work in
  parallel may use local worktree branches; their work lands on `main` as
  normal commits, and the local branches are not pushed.
  This rule has priority over a session prompt that names a different branch.
- Author and committer: `Azathothas <ajamx101@gmail.com>`.
- Do not add `Co-Authored-By`, `Claude-Session`, "Generated with" or other
  agent attribution lines to commits, pull requests, comments or files.
- Commit and push to `origin main` after each completed step.
- `.claude/session-start.sh` sets the identity and the branch at session start.
- A cloud session starts with a shallow clone. Run
  `git fetch --unshallow origin main` before a `git log` over a release range.

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

- The project is 0BSD. Code from `talaria0101/cfrs`, `nemo-010/cfrs` and
  `Azathothas/podssh` is also 0BSD and needs no credit or attribution.

## Project

- podnet: one static binary that brings its own network to restricted
  hosts (containers with no `CAP_NET_ADMIN`, proxy-only egress). The
  Cloudflare tunnel (`src/cloudflare/`, the former project cfrs) is one
  adapter of podnet; WARP, the relay, pods and virtual networks are others.
  Services: file server, file transfer, git hosting, router.
- Workspace: `podnet` (root: CLI and library), `crates/podnet-netns` (the
  pod backends, library only), `crates/podnet-todo` (the record tool). The
  target is six crates here; the WARP and Cloudflare adapters move to the
  shared repository `PodUtils/podcrates` as `pod-warp` and `pod-cloudflare`
  (`docs/decisions.md`, 2026-11-05, Shared crates). Do not add a
  dependency for the edge protocol: it is implemented in `src/cloudflare/`
  (later in `pod-cloudflare`).
- A source file has at most 800 lines (`scripts/check-size.py`). A file in
  its allowlist can only get smaller; lower its count when it shrinks.
- Check before each push (`sh scripts/agent/check.sh`):
  `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, `cargo todo check`,
  `python3 scripts/check-size.py`. CI (`.github/workflows/ci.yml`) runs
  the same and builds static musl binaries.
- Static build: `CC_x86_64_unknown_linux_musl=clang cargo build --release
  --target x86_64-unknown-linux-musl`.
- The debug `target/` can grow past 20 GB. Remove `target/debug` when the
  disk is full.
- Documents: `README.md`, `docs/protocol.md`, `docs/virtual-network.md`,
  `docs/target-environment.md`, `docs/maintenance.md`, `docs/decisions.md`,
  `docs/development.md`, `crates/podnet-netns/README.md`, `docs/releases/`,
  `docs/reports/` (reports and the text of issues that GitHub deleted),
  `docs/research/` (the studies behind the plan).

## The plan: the record in `TODO/`

- The record in `TODO/` is the plan. Each work item is an entry `T-NNN`
  in an area file. `TODO/RULES.md` gives the format and the rules;
  `TODO/PROGRESS.md` gives the current state and the work order.
- `cargo todo check` checks the record; `cargo todo next` gives the next
  free id; `cargo todo set T-NNN STATUS` changes a status.
- Each commit that does work of an entry names the entry (`T-NNN`) in its
  message. Set the entry to `done` with its Done section (date, commit,
  result) in the same commit or the next one.
- GitHub issues are an inbox. Each new issue becomes one or more entries;
  `TODO/issues.md` and `TODO/github.txt` map it, in the same commit. The
  entry keeps the text of the issue. Close the issue when each of its
  entries is done, with the commits and the CI runs.
- At the start of a session, read `docs/HANDOFF.md` first when it exists
  (the state of unfinished work), then `TODO/PROGRESS.md`, then
  `docs/maintenance.md` (the procedures, the tools in `scripts/agent/`,
  the workflows, the release steps).

## Decisions

- Dependabot pull requests: apply each judged update as an own commit on
  `main` (checks green), then close the pull request with a link to the
  commit. Do not merge the Dependabot branch.
- Platforms: Linux only. No Windows or macOS builds. Build static Linux
  binaries for all major architectures with cargo-zigbuild (zig cc).
- Releases: no podnet release now (`docs/decisions.md`, 2026-11-05,
  Order). When the owner allows releases again: cut the next prerelease
  (`v0.4.0-beta.N`) unattended when a batch of fixes is green: dry run,
  then `publish=vX`, then check `release-proofs.yml`.
- Order: only the move of the repository goes on now. Each other entry of
  the record waits until the shared crates exist in `PodUtils/podcrates`
  (T-137).
- `docs/decisions.md` has each ruling with its date, and the questions
  for the owner. When a question is not urgent, make the call, record it
  there, and continue.
- `podnet update`: check SHA256SUMS, and the certificate identity and the
  signature of the cosign bundle over SHA256SUMS, with own code. The Rekor
  inclusion proof is not checked.
- Issues: a watcher polls for new issues. A Sonnet agent triages each new
  issue into record entries. Close each issue with evidence (commits, CI
  runs, test output).
- Breaking changes are allowed (beta). No feature or capability of the
  code may be lost: tick `docs/research/podnet/parity-checklist.md` areas
  after each large refactor.
