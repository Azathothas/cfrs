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
