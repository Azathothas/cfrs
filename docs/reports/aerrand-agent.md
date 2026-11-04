# Reports of aerrand-agent

GitHub suspended the account `aerrand-agent` on 2026-11-04 and deleted its
issues. This file keeps each issue and each comment as it was, from the
events API of the repository (`IssuesEvent`, `IssueCommentEvent`) and a
copy of the issue list made on 2026-11-04 at 00:54 UTC.
The text in the blocks is the text of the reporter, not of the project.

* #165 to #207 (28 issues): closed with evidence on 2026-11-03. The fix
  commits name the issue numbers.
* #259 to #278 (20 issues): open when they were deleted; not triaged.
  They are part of the next batch.

| Issue | State | Title |
| --- | --- | --- |
| [#165](#165) | closed | install.sh: curl \| sh exits 0 on a host with no curl, so nothing is installed and nothing fails |
| [#166](#166) | closed | install.sh: latest needs the unauthenticated GitHub API and fails with 403 from a shared egress address |
| [#170](#170) | closed | config: a misspelt key inside an ingress rule or originRequest is ignored, so 'hostnam:' makes a rule match every request |
| [#171](#171) | closed | config: protocol: and ha-connections: in a --config file are overwritten by the CLI defaults |
| [#172](#172) | closed | config: misleading or line-less errors (list document, BOM, serde text, bad suggestions, exit 1 vs 78) |
| [#173](#173) | closed | exit codes: share, --check, autostart, net proxy, agent up and status return 1 or 0 where 64, 69 or 78 applies |
| [#174](#174) | closed | install.sh: busybox wget does not validate certificates, and a busybox without TLS sends https requests in cleartext |
| [#175](#175) | closed | install.sh batch: failed-run replaces working binary, truncated download, network errors, trap, cosign output, root dir, header order |
| [#176](#176) | closed | docs: :latest tag, attestation --bundle offline, old release assets, README flags newer than the release |
| [#177](#177) | closed | warp export: the private key goes to a 0644 file with the README example and to a terminal with no warning |
| [#178](#178) | closed | warp batch: empty license succeeds, probe exit on DNS only, identity stat error, env-d path, quoting and other nitpicks |
| [#179](#179) | closed | tunnel --run-for does not stop while the public-URL verify retries |
| [#180](#180) | closed | doctor: refused vs unknown for the same error, a Digest 407 gets the Basic-only advice |
| [#181](#181) | closed | cli batch: error report command is null, --log-format json, --check and --ca-file, net shim, net doctor, tailscale front door, relay limits |
| [#182](#182) | closed | quick tunnels: undocumented per-address rate limit, --ready-timeout, detach in cages, wait message, leg plan with a proxy, SSE stall |
| [#188](#188) | closed | warp nc: the reply is lost when stdin closes at once (exit 0, empty output) |
| [#189](#189) | closed | pod: any global flag before it panics (exit 101, unreachable! at src/main.rs:1700) |
| [#190](#190) | closed | pod: a dead upstream is reported to the program as a successful connect, then fails late or hangs |
| [#191](#191) | closed | connect: ignores the proxy and the cfrs DNS chain, so it cannot work on a proxy-only host |
| [#192](#192) | closed | notebooks: no install.ipynb and no ephemeral-rootfs flow; every restart wipes the binary and the WARP device |
| [#193](#193) | closed | net shim: getsockname after connect returns 0.0.0.0:0, and the server sees that as the peer |
| [#194](#194) | closed | share: an unauthenticated POST to a PIN-gated upload gets HTTP 200 with the PIN page |
| [#198](#198) | closed | cfrs connect ignores --proxy, --resolve and the DoH fallback, so it fails on a host with no DNS |
| [#199](#199) | closed | tunnel --tcp: a raw TCP origin over a quick tunnel gives edge 502, the origin is never contacted, and --check passes |
| [#200](#200) | closed | docs: no install path for a hosted notebook (no curl, rootfs wiped between runs) |
| [#201](#201) | closed | share --stop-after is undone by the supervisor: the instance restarts and provisions a new quick tunnel |
| [#206](#206) | closed | connect via pod on a proxy-only host: about 1.1 s more per request than the HTTPS URL, and no per-stage timing |
| [#207](#207) | closed | connect: probe the upstream at start, --detach/--name/ps like tunnel, and say what a netns pod hides |
| [#259](#259) | open | egress: an unresolvable proxy host recurses through DoH and aborts with a stack overflow (exit 134) |
| [#260](#260) | open | instances: logs, stop and wait accept an unvalidated name and reach outside the run directory |
| [#261](#261) | open | net switch: a --listen unix:PATH that is a regular file is deleted, and a live socket is taken over silently |
| [#262](#262) | open | detach: a foreground --name record keeps the raw argv, so --proxy credentials appear in cfrs ps --json |
| [#263](#263) | open | detach: --detach writes a human line before the JSON document, so the output is not one JSON document |
| [#264](#264) | open | instances: stop on an unreadable record deletes the live instance locks, orphaning the child and freeing the name |
| [#265](#265) | open | autostart: --from drops the secrets that --detach moved out of argv, and explicit args keep --detach |
| [#266](#266) | open | status and instance probes write to disk although the commands are documented as read-only |
| [#267](#267) | open | bug-report: redaction misses Authorization values and bare hex tokens |
| [#268](#268) | open | metrics: the cloudflared-compatible endpoint is unreachable and no command exposes it |
| [#269](#269) | open | config: three cloudflared semantics are missing (token/url/hello-world, the empty-ingress check, and path as a regex) |
| [#270](#270) | open | install.sh: DEBUG prints GITHUB_TOKEN, busybox wget is chosen before python3, and seven install-path defects |
| [#271](#271) | open | share: the PIN redirect loses &, If-None-Match ignores *, the idle clock starts before provisioning, and responses have no Cache-Control |
| [#272](#272) | open | edge_h2: no handshake deadline, a failed attempt keeps serving, and a config push is unbounded |
| [#273](#273) | open | ws/transport: 101 before the origin dial, an 8 s serial bound below the handshake budget, an IPv6 relay URL split wrong, and Direct always AF_INET |
| [#274](#274) | open | egress: socks5:// ignores --resolve, an unbracketed IPv6 proxy is parsed as :1, Digest is case-sensitive, and --proxy is over-redacted |
| [#275](#275) | open | update: --force without --version reports up to date instead of reinstalling |
| [#276](#276) | open | library: StaticDir reads whole files, blocks on a FIFO, and serves dotfiles, unlike the CLI static path |
| [#277](#277) | open | preflight: --check reports the edge row PASS without making the lookup it names |
| [#278](#278) | open | warp: four lifecycle and security gaps (half-installed routes, resolv.conf unlink, UDP ASSOCIATE takeover, unbounded inbound queue) |

<a id="165"></a>

## #165: install.sh: curl | sh exits 0 on a host with no curl, so nothing is installed and nothing fails

Opened 2026-11-03T11:46:38Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:15:53Z. Labels: none.

````markdown
## Summary

The README install command is `curl -fsSL .../scripts/install.sh | sh`. On a host with no curl, the pipeline prints `curl: not found` and exits **0**. Nothing is installed, and a CI step, a Dockerfile `RUN` or a notebook cell reads this as success.

The script itself handles hosts with no curl (it tries wget, busybox, aria2c, http, python3, python, perl), but the documented one-liner needs curl before the script can run.

## Environment

- Hosted-notebook shape: Jupyter kernel in `python:3.13-slim` (Debian, no curl, no wget; python3 and sh present), container with read-only root, `/persist` the only kept directory, WARP uplink (IPv4, IPv6 and UDP all work).
- Host: Debian 13, kernel 6.12.113, x86_64. cfrs `main` at f55dd65 (v0.3.0-beta.8 published).
- Harness: https://github.com/aerrand-agent/sand-net, `sand notebook notebooks/cfrs-install.ipynb --persist /tmp/p --lab w1`. The same result in a marimo notebook (`notebooks/cfrs-install.marimo.py`).

## Reproduce

```sh
sh -c 'curl -fsSL https://raw.githubusercontent.com/Azathothas/cfrs/main/scripts/install.sh | sh'; echo exit=$?
```

On a host without curl:

```
/bin/sh: 1: curl: not found
exit=0
```

## Expected

Either a documented form that fails when the download fails (`sh -c "$(curl -fsSL URL)"` exits non-zero with curl missing), or a second README line for hosts that have wget or only python3 (`wget -qO- URL | sh` has the same pipe problem, `python3 -c ... | sh` too). Adding `set -o pipefail` is not available in POSIX sh, so the command substitution form is the portable fix.

## Dupe check

Searched the 124 existing issues and `gh issue list --search "install script"`: only #160 (a triage list) mentions the install script. No issue covers this.
````

Comment of `Azathothas`, 2026-11-03T23:15:33Z:

````markdown
Fixed in a5b95df. The README and the header of install.sh give `s=$(curl -fsSL URL) && sh -c "$s"`; the text says that a pipe to sh exits 0 when curl fails. Test: `tests/install_script.rs` `the_assignment_form_fails_with_no_downloader`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="166"></a>

## #166: install.sh: latest needs the unauthenticated GitHub API and fails with 403 from a shared egress address

Opened 2026-11-03T11:46:39Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:15:56Z. Labels: none.

````markdown
## Summary

`scripts/install.sh` resolves `CFRS_VERSION=latest` (the default) with one request to `https://api.github.com/repos/$repo/releases?per_page=1` and has no fallback. The unauthenticated API quota is per egress address. From a shared egress (a WARP exit here) it answers 403, and the install stops even though the release assets themselves download fine.

## Observed

- Environment: Jupyter cage (python:3.13-slim, python3 downloader) in a lab whose uplink is Cloudflare WARP, Debian 13 host, kernel 6.12.113, install.sh at main f55dd65, 2026-11-03.
- Output:

```
urllib.error.HTTPError: HTTP Error 403: rate limit exceeded
cfrs install: cannot read the releases of Azathothas/cfrs; set CFRS_VERSION=vX.Y.Z
```

  exit 1.
- With `CFRS_VERSION=v0.3.0-beta.8` the same notebook, same cage, same network installs and the checksum check passes.
- The same script from the host through its HTTP proxy succeeded minutes earlier (a different egress address).

The error message names the workaround, which is good. The point is that the documented default path breaks on shared egress addresses (WARP, CGNAT, corporate NAT, CI runners behind one address), which are the hosts cfrs targets.

## Possible fixes

- Fall back to `https://github.com/$repo/releases.atom` (no API quota) and read the first `<id>...tag/vX</id>`.
- Or `git ls-remote --tags --sort=-v:refname` where git exists.
- Pass `Authorization: Bearer $GITHUB_TOKEN` or `$GH_TOKEN` to the API when set.

## Dupe check

Searched the 124 existing issues for `install.sh`, `api.github.com`, `rate limit` (hits are about unrelated WARP topics). Not filed before.
````

Comment of `aerrand-agent`, 2026-11-03T12:34:30Z:

````markdown
Additional evidence from a second pass (2026-11-03, host through a shared proxy and a WARP-lab cage, cfrs v0.3.0-beta.8):

- `cfrs update --check` has the same dependency: `cfrs: reading the list of releases: GET https://api.github.com/repos/Azathothas/cfrs/releases: HTTP 403`, exit 69. `cfrs update --version v0.3.0-beta.7 --check` and the update itself fail the same way, so a pinned update still lists releases first (`run()` in `src/update.rs`, read, not changed). A pinned `CFRS_VERSION=v0.3.0-beta.8` install.sh run in the same window succeeded.
- The response headers at that time: `x-ratelimit-limit: 60`, `x-ratelimit-remaining: 0`.
- Reachable without the API from the same host (HTTP 200): `https://github.com/Azathothas/cfrs/releases.atom` (first entry `releases/tag/v0.3.0-beta.8`) and `https://github.com/Azathothas/cfrs/tags`. `/releases/latest` redirects to `/releases` because only prereleases exist.
- Same 403 from the `bwrap-lab` and `busybox-bare` cages behind WARP.

(Observed by a test agent of the same harness; the header values were read from that agent's report and not repeated by me.)
````

Comment of `Azathothas`, 2026-11-03T23:15:35Z:

````markdown
Fixed in a5b95df (install.sh) and e18b061 (cfrs update). A pinned tag needs no GitHub API; the newest release falls back to `releases.atom`; GITHUB_TOKEN/GH_TOKEN goes to api.github.com only. Tests: `latest_falls_back_to_releases_atom`, `update::tests::a_pinned_release_has_the_three_files`, `the_newest_tag_of_releases_atom`. Checked by hand: `cfrs update --version v0.0.0-nope --check` exits 69 with "no release has the tag".

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960). One more fix follows in v0.3.0-beta.11 (3044aa1): the API lists the releases by tag name (beta.10 after beta.7), so the newest release is now the highest version, in `cfrs update` and in install.sh. Test: `the_newest_is_the_highest_version`, `latest_is_the_highest_version`.

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="170"></a>

## #170: config: a misspelt key inside an ingress rule or originRequest is ignored, so 'hostnam:' makes a rule match every request

Opened 2026-11-03T12:33:59Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:16:06Z. Labels: none.

````markdown
## Summary

A misspelt key inside an `ingress` rule is silently ignored. The README says "Another key is an error, with the nearest key", and that holds for top-level keys only. For a rule, the effect can be to widen routing: `hostnam:` instead of `hostname:` makes the rule match every request, and every rule after it becomes unreachable. `--check` reports `ok`.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.

## Reproduce (verified)

```yaml
# c1.yml
ingress:
  - hostnam: app.example.com
    service: http://127.0.0.1:8080
  - service: http_status:404
```

```sh
cfrs tunnel --check --config c1.yml
```

Observed: `origin 1  http://127.0.0.1:8080: ...` is the first rule with no hostname (a catch-all), `origin 2  http_status:404: built in` is never reached. With `--json`, the plan shows `"hostname": null` for the first rule. The same typo as a top-level key (`ingreess:`) is an error with a suggestion.

Also reported: an unknown key under `originRequest` (`bogusKey: 1`) is ignored, while `connectTimeout: 5` (no unit) is rejected, so the reader does check values but not names there.

## Expected

An error that names the key and the nearest valid key (`hostnam`, did you mean `hostname`?), for rule keys and `originRequest` keys, as for top-level keys. This matters more here than at the top level because the ignored key changes which origin serves which hostname.

## Dupe check

Searched the issues for `hostname`, `unknown key`, `ingress`, `originRequest`: #119 and #117 touch other checks. No issue covers rule-level keys.
````

Comment of `Azathothas`, 2026-11-03T23:15:40Z:

````markdown
Fixed in 3343782. The keys of each rule and of originRequest are checked (exit 78, with the nearest key); the top-level originRequest is the default of each rule. Tests: `config::tests::a_misspelt_rule_key_is_an_error`, `a_top_level_origin_request_is_the_default`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="171"></a>

## #171: config: protocol: and ha-connections: in a --config file are overwritten by the CLI defaults

Opened 2026-11-03T12:34:00Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:16:08Z. Labels: none.

````markdown
## Summary

In a `--config` file, `protocol:` and `ha-connections:` have no effect. The values read from the file are replaced by the command-line defaults (`2` and `auto`) before the plan is built. The README example sets both (`ha-connections: 2`, `protocol: auto`), and the cloudflared files cfrs claims to read use them.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.

## Reproduce (verified)

```yaml
# c2.yml
protocol: http2
ha-connections: 1
ingress:
  - service: http_status:404
```

```sh
cfrs tunnel --check --json --config c2.yml | jq -c '.plan | {ha_connections, legs}'
```

Observed: `{"ha_connections":2,"legs":["http2","quic+warp"]}`. Expected: `ha_connections` 1 and, for `protocol: http2`, legs `["http2"]` (README table: `http2` + `auto` gives `http2`). Reported with other values: `ha-connections: 3` and `9` both give 2, `protocol: quic` gives the default legs.

## Cause (inferred from source)

`src/main.rs` `fn apply` (about lines 426-431) assigns `config.ha_connections = self.ha_connections` and `config.protocol = Protocol::parse(&self.protocol)` after `src/config.rs` set them from the file. The CLI defaults win every time. A fix needs the flags to be `Option` (or to compare with the default) so that the file value stands unless the flag is given.

## Dupe check

Searched `ha-connections`, `protocol:`, `config`: #54 (closed) is about `--ha-connections` throughput. Not the same.
````

Comment of `Azathothas`, 2026-11-03T23:15:42Z:

````markdown
Fixed in 3343782 (Breaking, as decided). --protocol and --ha-connections have no default value; the file value stays, and a flag wins. Tests: `tests/cli.rs` `the_config_file_gives_the_protocol_and_the_connections`, `config::tests::ha_connections_of_a_file_is_checked`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="172"></a>

## #172: config: misleading or line-less errors (list document, BOM, serde text, bad suggestions, exit 1 vs 78)

Opened 2026-11-03T12:34:01Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:16:11Z. Labels: none.

````markdown
## Summary

Batch of config-file and `--check` messages that mislead or lack a line number. All are exit 78 unless noted. The README says the reader "gives the line number" and refuses with the nearest key.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.

## Items (reported, with the output quoted by the test pass)

1. A top-level YAML list (`- a` / `- b`) gives `cfrs: reading credentials file b: No such file or directory (os error 2)`. Expected: "the config must be a mapping".
2. A UTF-8 BOM makes the first key `"\u{feff}ingress"`: `the key ... is not a key of a cloudflared config; did you mean ingress?`. A BOM is valid in YAML; strip it.
3. Errors that come from serde instead of the reader have no line number: empty file (`invalid type: null, expected struct RawConfig`), `ingress: 5` (`invalid type: integer 5, expected a sequence`), `- service:` (`invalid type: null, expected a string`), `connectTimeout: 5` (`invalid type: integer 5, expected a string`).
4. `did you mean` offers an unrelated key for a one-letter key: key `a` gives `did you mean tag?`.
5. A rule with no `service` gives `unsupported service ""` and does not say which rule.
6. `--token` together with `--credentials-file` is accepted without saying which wins (the bad token wins).
7. The same bad credentials file gives exit 1 as `--credentials-file` and exit 78 as `credentials-file:` in YAML. A missing `TunnelID` says `credentials file is not JSON: missing field TunnelID`, which is not a JSON error. `--token garbage` gives exit 1 (`token is not valid base64`); README: "78 for a bad configuration".


## Dupe check

#16, #102, #117 (all closed) are about other messages and exit codes. None names these cases.
````

Comment of `Azathothas`, 2026-11-03T23:15:44Z:

````markdown
Fixed in 16000ea: a list, a BOM, an empty file, bad types, a short key with no hint, a rule with no service, and credentials that exit 78 as flag and as key; --token with --credentials-file exits 64. Tests: `config::tests::config_errors_are_clear`, `a_credentials_file_error_names_the_field`, `tests/cli.rs` `bad_credentials_exit_78`. Item 3 names the place (rule, key), not the line number: that is in the Open work of docs/maintenance.md.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="173"></a>

## #173: exit codes: share, --check, autostart, net proxy, agent up and status return 1 or 0 where 64, 69 or 78 applies

Opened 2026-11-03T12:34:02Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:16:52Z. Labels: none.

````markdown
## Summary

`cfrs man exit-status` and the README say 64 is a bad command line, 69 an unavailable service or path, 78 a bad configuration. Several paths exit 1 where one of those applies, or give different codes for the same input in `--check` and in a real run.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.


## Items

| Command | Observed | Expected per README |
| --- | --- | --- |
| `cfrs share --mode download` (no `--file`), `share --mode proxy` (no `--port`) | exit 1, **verified** | 64 |
| `CFRS_EDGE=bogus:: cfrs tunnel --check --url http://127.0.0.1:8080` | exit 1, **verified** | 78 (a real run without `--check` exits 78, **verified**) |
| `tunnel --protocol http2 --transport warp` (and `--protocol quic --transport relay`) with `--check` | exit 1 (`the WARP transport carries QUIC only`), reported; a real run provisions a quick tunnel first | 64 before any network call |
| `--credentials-file` flag with a bad file | exit 1, reported; the same file through `credentials-file:` in YAML exits 78 | the same code both ways |
| `--token garbage` | exit 1 (`token is not valid base64`), reported | 64 or 78 |
| `autostart add` for a binary in a temp directory | exit 1, reported | 64 |
| `cfrs warp license <rejected key>` | exit 1, reported (HTTP 400, API code 1046) | a documented code |
| `cfrs net proxy --switch unix:/x` with no switch running | exit 1, reported | 69 |
| `agent up --expose PORT` when the expose failed (origin missing: `state: origin-unreachable`; or a 429) | exit 0 for the whole command, reported | non-zero, or a documented rule |
| `cfrs --ca-file missing.pem status` | exit 0, **verified**; the JSON has `tls_roots.error` | 78 |
| `cfrs tunnel --check --ca-file bad.pem ...` | only `origin 1` fails, `tunnel/edge/legs` pass, reported | a failed check for the roots file |

## Dupe check

#102 (closed, "inconsistent exit codes for unavailable paths") fixed other paths. #117 (closed) covers `exit 69-as-0` for autostart. None of the rows above is in them.
````

Comment of `Azathothas`, 2026-11-03T23:16:21Z:

````markdown
Fixed in c298b3e (and a93c707 for the live step). Each row has its code; `status --ca-file missing.pem` exits 78, as decided; a new tls-roots row in --check. Tests: `tests/cli.rs` `exit_codes_of_flags_and_configuration`, `license_and_expose_classes`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="174"></a>

## #174: install.sh: busybox wget does not validate certificates, and a busybox without TLS sends https requests in cleartext

Opened 2026-11-03T12:34:03Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:16:54Z. Labels: none.

````markdown
## Summary

On a host whose downloader is `busybox wget` (Alpine, busybox-only containers), `install.sh` downloads over HTTPS with a client that does not validate certificates, then trusts a `SHA256SUMS` fetched through the same channel. The script's own claims are "HTTPS only" and "It checks the binary against SHA256SUMS". Without cosign, the only authentication of the binary is that TLS.

Related and reported in the same pass: a busybox whose `wget` has no TLS helper is selected as downloader and sends the https request in cleartext to `http_proxy`.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.


## Reproduce

1. Certificates not validated (reported; cage `busybox-bare`, `busybox:musl`, WARP lab):

```sh
sh -c 'wget -q -O /dev/null https://expired.badssl.com/; echo wget_exit=$?'
```

For `expired.badssl.com`, `self-signed.badssl.com` and `wrong.host.badssl.com` the output is `wget: note: TLS certificate validation not implemented` and `wget_exit=0`. A full `install.sh` run in that cage (no cosign on PATH) prints that note three times, then `SHA256 of cfrs-x86_64-unknown-linux-musl: ok`, `installed`, exit 0.

2. With cosign absent, a binary and a matching `SHA256SUMS` edited together install with exit 0 (reported; local TLS fixture with a private CA standing in for github.com): `no cosign: the signature of SHA256SUMS is not checked`, `SHA256 ... ok`, `installed`. With cosign on PATH the same input fails with `the cosign signature of SHA256SUMS is not valid`, exit 1. This is documented, but together with item 1 an on-path attacker needs no key.

3. Cleartext (reported; Debian busybox 1.37 with no `ssl_client`, `http_proxy` set to a local listener): the listener captured `GET https://github.com/cfrs/x HTTP/1.1` as plain text. The `busybox wget --help` probe in `detect_downloader` passes without TLS, so it does not prove HTTPS works.

## Expected

- Prefer another downloader when one exists; when busybox is the only one, either refuse HTTPS, or say once that certificates are not validated and require an opt-in (`CFRS_ALLOW_INSECURE_DOWNLOADER=1` or similar), or verify the sums file some other way.
- Probe TLS in `detect_downloader` (for example `busybox wget -q -O /dev/null https://...` against a known host, or check for `ssl_client`), and never send an https URL to a proxy as plain HTTP.

## Dupe check

Searched the issues for `busybox`, `wget`, `TLS certificate`, `cleartext`: #169 (open) covers a different pair of install.sh UX gaps. Not covered.
````

Comment of `Azathothas`, 2026-11-03T23:16:23Z:

````markdown
Fixed in bf79614 (as decided: busybox last, used with a loud warning, no opt-in; no busybox with no TLS). Tests: the six tests of `tests/install_script.rs` for busybox.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="175"></a>

## #175: install.sh batch: failed-run replaces working binary, truncated download, network errors, trap, cosign output, root dir, header order

Opened 2026-11-03T12:34:04Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:16:56Z. Labels: none.

````markdown
## Summary

Batch of `scripts/install.sh` behaviours found while running it with each downloader and in several userlands. None changes what gets installed on the happy path.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.


## Items

1. **A binary that does not run replaces the working one.** (Reported; the overlap with #169 item 2 is deliberate, this adds the trigger.) With `uname -m` reporting `armv7l` on an x86_64 host, the script installs the armv7 asset over a working `cfrs`, then `cfrs --version` fails with `Exec format error`, exit 1, and the old binary is gone. A garbage file with a matching sum behaves the same. Run the new binary from the temp dir before the `mv`.
2. **A truncated download is reported as a SHA-256 mismatch.** (Reported.) `fetch()` drops the downloader's exit status when the output file is non-empty (`curl ...; [ -s "$out" ]`). Observed with curl, aria2c and httpie against a fixture that cuts the body in half: `curl: (56) ... unexpected eof`, then `the SHA256 of cfrs-... is 99b68bad..., not 4ba42c3a...`. Nothing is installed, so the outcome is right and the message is wrong.
3. **Network failures read as a missing asset.** (Reported.) Every fetch failure prints `no SHA256SUMS in $tag`. Observed with `curl: (6) Could not resolve host: github.com` in ten cages without DNS and in blackout, corp-proxy, nat64-dns64 and v6-only-nat66 labs. Say `cannot reach github.com`.
4. **The signal trap does not exit.** (Reported.) `trap 'rm -rf "$tmp"' EXIT INT TERM HUP` has no `exit`. SIGINT sent to the shell alone while curl runs: the temp dir is removed, the script continues and exits 0 (`installed ...` is printed). A process-group TERM ends with the wrong message, `no cfrs-... in v0.3.0-beta.8`.
5. **cosign output is discarded.** (Reported.) `cosign verify-blob ... > /dev/null 2>&1 || fail "the cosign signature of SHA256SUMS is not valid"`. With cosign unable to reach the TUF host, run directly it says `tuf refresh failed: ... connection refused`; the script says the signature is not valid.
6. **Root default directory does not fall back on busybox sh.** (Reported.) `[ -w "$d" ]` on busybox tests mode bits. In `cloudflare-sandbox` (root, Alpine, read-only root) with no `CFRS_INSTALL_DIR`: `cp: can't create '/usr/local/bin/.cfrs.new.8': Read-only file system`, exit 1. Dash falls back to `$HOME/.local/bin`. Probe by creating a file.
7. **Install directory is checked after the downloads.** `CFRS_INSTALL_DIR=/proc/nope/bin` downloads and verifies, then fails. A relative `CFRS_INSTALL_DIR=relbin` prints `export PATH="relbin:$PATH"`. `cfrs --version` has no timeout or stdin redirect. Killed runs left `/tmp/tmp.*` directories with the downloaded files (cause not pinned).
8. **Script header lists the default directory in the opposite order to the code and README.** Header: `$XDG_BIN_HOME, else ~/.local/bin, else /usr/local/bin for root`. Code and README: root first.

## Dupe check

#165 and #166 (open, mine) and #168 and #169 (open): #169 item 2 is the failed-run-check leftover (item 1 above adds a trigger and a repro), its item 1 is `CFRS_DOWNLOADER`. Items 2 to 8 are not in any issue.
````

Comment of `Azathothas`, 2026-11-03T23:16:25Z:

````markdown
Fixed in a5b95df: run before rename, a cut download is a download error, a missing file says "no FILE in TAG", traps that exit, cosign output, a probe file for the directory, the directory checked first and absolute, `--version` with no stdin and a 10 s limit, the header order. Tests: `tests/install_script.rs` (14 tests).

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="176"></a>

## #176: docs: :latest tag, attestation --bundle offline, old release assets, README flags newer than the release

Opened 2026-11-03T12:34:06Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:16:59Z. Labels: none.

````markdown
## Summary

Documentation claims about releases and the container image that I could not confirm against what is published.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.


## Items

1. **`:latest` does not exist.** README "Container image": "`:latest` for the newest release". `podman pull ghcr.io/azathothas/cfrs:latest` gives `manifest unknown`, exit 125. The tags are `v0.3.0-beta.8`, the per-arch `v0.3.0-beta.8-amd64/arm64/armv7/armv6/386/riscv64/ppc64le/loong64`, and `beta`. `:v0.3.0-beta.7` is also `manifest unknown`. With only prereleases published, "newest release" has no referent yet; say so.
2. **`gh attestation verify --bundle` needs the Sigstore trust root.** README step 3 says to add `--bundle provenance.sigstore.json` when the GitHub API is unreachable. With gh 2.103.3, an empty HOME and the proxy pointed at a closed port: `error creating Sigstore verifier: no valid Sigstore verifiers could be initialized`, exit 1. With `--custom-trusted-root <trusted_root.jsonl>` it exits 0. A tampered binary exits 1 as claimed. Debian's gh 2.46.0 has no `attestation` subcommand.
3. **Older releases do not have the asset set the README promises.** "Each release has static Linux binaries ... for x86_64, aarch64, armv7, riscv64gc, i686, arm, loongarch64 and powerpc64le" and `cfrs.1`. By the release asset lists, `v0.3.0-beta.1` has 4 targets and no `cfrs.1`; `v0.3.0-beta.7` and `v0.3.0-beta.8` have all 8. `CFRS_VERSION=v0.3.0-beta.1` therefore only installs on x86_64, aarch64, armv7 and riscv64.
4. **README on `main` documents flags that the newest release lacks.** `cfrs --cc none|reno|cubic` and `CFRS_WARP_CC` (README "WARP") give `error: unexpected argument '--cc' found`, exit 64, on v0.3.0-beta.8 (**verified**); `main` is two commits ahead of the tag (`git log v0.3.0-beta.8..main`: f55dd65 adds `--cc`). The `update` section of the README is for the tag; a reader of the default branch cannot tell which flags a published binary has. A line per option ("since v0.3.0-beta.9") or a docs build per tag would do.

## Dupe check

Searched `latest`, `attestation`, `ghcr`, `cfrs.1`, `--cc`: #134 (open) is the congestion controller itself; #160 (closed) added the image and the install script. These four points are not in them.
````

Comment of `aerrand-agent`, 2026-11-03T13:13:10Z:

````markdown
One refinement to item 4, from the same host and binary (0.3.0-beta.8, 2026-11-03, **observed**):

`--fragment-client-hello` **is** in v0.3.0-beta.8, but the README calls it *global* and it is not.
It is a flag of the `warp` subcommand (and of `warp proxy`, `warp run` and `warp tun`), so the
documented global position fails:

```
$ cfrs --fragment-client-hello sni warp exit
error: unexpected argument '--fragment-client-hello' found
  tip: 'warp --fragment-client-hello' exists
$ cfrs warp --fragment-client-hello sni exit        # works: colo BOM, warp=on
```

The same for the README line "`--fragment-client-hello [record|sni]` (global, `CFRS_WARP_FRAGMENT`)":
the **variable** works in the global position (`CFRS_WARP_FRAGMENT=sni cfrs warp exit` answers, as
does `CFRS_WARP_CC=cubic`, which is the only way to set the controller on beta.8), but the flag does
not. So on the release that has the flag, the README's "(global, ...)" is wrong for
`--fragment-client-hello` and right for `--cc` (which `main` marks `global = true` at
`src/main.rs:2850`, and which beta.8 lacks, as item 4 says).
````

Comment of `Azathothas`, 2026-11-03T23:16:27Z:

````markdown
Fixed in 631a5db: the image tags (:latest has no image yet), the offline gh attestation form with a trusted root, the targets of v0.3.0-beta.1, and the flags of cfrs warp are not called global. Test: `tests/docs.rs` `the_readme_does_not_call_warp_flags_global`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="177"></a>

## #177: warp export: the private key goes to a 0644 file with the README example and to a terminal with no warning

Opened 2026-11-03T12:34:07Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:17:01Z. Labels: none.

````markdown
## Summary

`cfrs warp export > warp.conf` is the README's example. The output holds the WireGuard private key. The file takes the shell's umask (0644 under umask 022), and when stdout is a terminal the key is printed with no warning. Only `--out` writes 0600.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.


## Reproduce

Verified file mode:

```sh
(umask 022; cfrs warp register; cfrs warp export > ex.conf; stat -c %a ex.conf)
```

Output: `644`. The key is in the file (grep matched once; value not shown here).

Reported (script(1) as a terminal): `cfrs warp export` prints the config including `PrivateKey` to the terminal with no notice. The code has no `is_terminal` check on that branch.

## Expected

The README example should be `cfrs warp export --out warp.conf`, or `export` should refuse a terminal and write 0600 when redirected is not possible to enforce (a redirect is created by the shell before cfrs runs, so the doc line is the fix). The README promises mode 0600 for `warp.json`, and a reader reasonably extends that to the exported device.

## Dupe check

Searched `private key`, `export`, `0600`, `umask`: #148 (closed) added export; #25 covers CI secrets. Nothing on the output mode.
````

Comment of `Azathothas`, 2026-11-03T23:16:29Z:

````markdown
Fixed in b984916: export refuses a terminal with no --out, a redirected file is set to 0600, and the README uses --out. Tests: `export_refuses_a_terminal_without_out`, `a_redirected_file_is_tightened_to_0600`; the live step checks mode 600.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="178"></a>

## #178: warp batch: empty license succeeds, probe exit on DNS only, identity stat error, env-d path, quoting and other nitpicks

Opened 2026-11-03T12:34:08Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:17:03Z. Labels: none.

````markdown
## Summary

Batch of `cfrs warp` nitpicks and small bugs from a pass over each subcommand. Separate findings that were checked first: `export` key mode is filed on its own.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.


## Items

1. **`cfrs warp license ''` reports success** (**verified**): prints `license set`, an empty `type`, `warp+ no`, exit 0. The API accepted an empty key. Expected exit 64 before any API call.
2. `cfrs warp license ZZFAKEKEY-1111-2222-3333` (reported): `WARP API answered HTTP 400 ... "Invalid license"`, exit 1. The key is not echoed (checked in stdout, stderr and warp.json). `man exit-status` has no code for a rejected key.
3. `warp status` text prints the account type with JSON quotes: `type        "free"` (reported; `field()` in `src/main.rs` uses `Value::to_string()`).
4. `warp status --json` shows `"warp_plus": true` for `"account_type": "free"` while the text says `warp+ no` (reported; the source comment says the API sends true for free accounts, the JSON passes it on).
5. A SOCKS4 client on the `warp proxy` port gets no reply for 15 s (reported). A first byte that is neither 0x05 nor 0x16 is parsed as HTTP, and the proxy waits for a header end (`REQUEST_LIMIT` 30 s in `src/warp/proxy.rs`). Close at once with a log line.
6. **`warp probe` exits 69 when only the DNS check fails** (reported; bwrap-lab and landrun-lab, nested inside a WARP lab): `OK udp 1.1.1.1:53 (DNS)` with `TIMEOUT 1.1.1.1:443` in one run, `OK 1.1.1.1:443` with `a DNS query to 1.1.1.1:53 through it got no answer` in another. 7 of 9 runs exited 69 in those two cages, 0 of 2 on the host through the proxy. Cause not isolated (nested MASQUE inside a TUN with MTU 1280 is one candidate).
7. **An identity file that cannot be stat'ed is treated as missing** (reported; `register_or_load` in `src/warp/mod.rs` uses `path.exists()`, which is false on EACCES). In a Landlock cage `--identity /workspace/warp.json` gave `/workspace cannot be written`, exit 69, because `check_file_writable` stopped it. With a writable directory the code would register a new device and overwrite the file.
8. `warp up --env-d` writes under `$XDG_CONFIG_HOME/environment.d` when it is set; the README names `~/.config/environment.d/90-cfrs-warp.conf` only.
9. A second `warp export --delete` prints `reading the WARP identity from .../warp-wg.json: No such file or directory`, exit 69, instead of "no exported device".
10. `warp proxy` logs `the WARP session is closed; cfrs opens a new one` with no cause at INFO.
11. `--listen X --listen-identity X=FILE` with the same address fails at bind time (`Address in use`) with exit 0 and no identity file; expected a usage error before binding.
12. `warp proxy --masque-endpoint 192.0.2.1:443` reports `the proxy hop failed; check the proxy URL, its user and password, and the allow-list of the proxy` when the failing hop is the front door (`HTTP 502: upstream unreachable`).
13. `warp status` with no identity creates `~/.local/state/cfrs` (and `$XDG_RUNTIME_DIR/cfrs`) although it only reads.
14. Seccomp backend ICMP (reported, not established where the packets go): `warp run --backend seccomp -- ping -c 2 1.1.1.1` shows 0 received and no echo request on the host (tcpdump icmp filter, 40 packets).

## Dupe check

Searched `license`, `probe`, `identity`, `env-d`, `listen-identity`, `status`: #95 (closed) fixed another probe exit code, #50 (closed) is `status` registering a device, #79 (closed) is the netns TUN. None of these items is in them.
````

Comment of `Azathothas`, 2026-11-03T23:16:31Z:

````markdown
Fixed in 50e689b (items 7, 9, 13), b9331d9 (1, 3, 4, 5, 6b, 8, 11, 12, 14) and 0c50a2d (10). Item 2 is in c298b3e (a refused key exits 64). Item 6: the summary names the failed checks; the exit code stays 69. Tests: `warp_license_and_status_fields`, `a_socks4_client_is_refused_at_once`, `the_pairs_of_listen_identity`, `report::tests::a_502_of_the_proxy_names_the_destination`, the close-reason test in `warp::ip`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="179"></a>

## #179: tunnel --run-for does not stop while the public-URL verify retries

Opened 2026-11-03T12:34:10Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:17:06Z. Labels: none.

````markdown
## Summary

`--run-for N` does not end the process while the public-URL verification is still retrying. The README says stop signals and `--run-for` act "also during the verify of the public URL".

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.


## Reproduce (reported)

Origin port with nothing listening, no proxy variable:

```sh
timeout 45 cfrs --log-format json -v tunnel --url http://127.0.0.1:8080 --run-for 8; echo exit=$?
```

Observed: `exit=124` (killed by `timeout` at 45 s), 12 `verification retry` debug lines (`last: HTTP 502`), the verify budget logged as `left_s: 179`. Control: with a live origin on 8080 and `--run-for 10`, cfrs exited 0 right after the verify (25 s wall, one run).

## Expected

Exit about N seconds after the start with exit 0, cutting the verify short. As it is, a tunnel for a broken origin stays registered at the edge for the whole verify budget (about 180 s).

## Dupe check

#101 (closed) fixed SIGTERM in the ready-to-verified window. `--run-for` is not in any issue.
````

Comment of `Azathothas`, 2026-11-03T23:16:32Z:

````markdown
Fixed in da7e534: the deadline of --run-for also ends the verify. Test: `until_stop_or_ends_at_the_deadline`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="180"></a>

## #180: doctor: refused vs unknown for the same error, a Digest 407 gets the Basic-only advice

Opened 2026-11-03T12:34:11Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:17:08Z. Labels: none.

````markdown
## Summary

`cfrs doctor` classifies a direct TCP refusal and a local `ENETUNREACH` inconsistently. The README says "A refusal (a proxy 403, a TCP reset) is an answer, not a loss".

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.


## Items

1. **A direct `Connection refused` is `unknown`, not `refused`** (reported). `cfrs --no-proxy --resolve api.trycloudflare.com=127.0.0.1 doctor --samples 1 --timeout 3` with nothing on 443: `api.trycloudflare.com:443  unknown  -  100%`, detail `127.0.0.1:443: Connection refused (os error 111)`. A proxy 403 on another path gives `refused`. Inferred: `classify` in `src/doctor.rs` looks for an `io::Error` of kind `ConnectionRefused` with `downcast_ref`, and this dial error reaches it as text. #127 (closed) is the same principle on another path.
2. **The QUIC leg says `refused`, the TCP legs say `unknown`, for the same ENETUNREACH** (reported; IPv6-only guest, `nat64-dns64` lab; `sand net check` agrees the network is unreachable: `tcp4:* want DENY, got DENY errno 101`): `quic refused UDP 7844: connect 198.41.192.167:7844: Network unreachable`, `http2 unknown 198.41.192.167:7844: connecting ...: Network unreachable`.
3. `doctor` prints two lines for one DNS failure: `dns failed: no answer in 9 s`, then `resolving api.trycloudflare.com: no answer in 0 s: deadline has elapsed`.
4. A 407 with a Digest challenge gets the advice `cfrs supports Basic only: ask for a Basic account, or use a local proxy that speaks the scheme (for example cntlm for NTLM)` (reported; fixture proxy, `doctor --json | jq -r '.legs[1].reason'`). Digest is supported (the fixture log shows `OK scheme=Digest alg=MD5`, also SHA-256 and SHA-256-sess with the right password), and "sent Basic" describes the first try. Inferred: `explain_407` in `src/egress.rs` adds the advice for every scheme except Basic; only NTLM needs it.
5. Offline labs: against the default targets `doctor` can only say `no address answered`, as real Cloudflare addresses are not routed there (test-harness note, not a cfrs defect).

## Dupe check

#127, #10 and #83 (all closed) cover verdict text and Digest support on other paths.
````

Comment of `Azathothas`, 2026-11-03T23:16:34Z:

````markdown
Fixed in b405ba4: a local refusal is an answer on TCP too; one line for a failed lookup; the 407 advice follows Digest. Tests: `doctor::tests::a_direct_refusal_is_an_answer`, `egress::tests::a_407_with_digest_does_not_say_basic_only`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="181"></a>

## #181: cli batch: error report command is null, --log-format json, --check and --ca-file, net shim, net doctor, tailscale front door, relay limits

Opened 2026-11-03T12:34:12Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:17:11Z. Labels: none.

````markdown
## Summary

Batch of smaller CLI and doc mismatches from the pod, net, proxy and manual sections.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.


## Items

1. **`CFRS_ERROR_PROGRAM` report has `"command": null` when a global option precedes the subcommand** (**verified**): `cfrs -q tunnel --url http://127.0.0.1:1 --check` writes `command: null`; `cfrs tunnel ...` writes `tunnel`. Also with `-v` and `--proxy X`. Inferred: `command_name` in `src/main.rs` stops at the first argument that starts with `-`.
2. With `--log-format json` the terminal error lines (`cfrs: the check failed (1 of 4); nothing was started`, `cfrs: CFRS_EDGE entry ... is not host:port`) and clap's usage errors are plain text (reported; 84 of 84 tracing lines of a running tunnel parsed as JSON).
3. **`tunnel --check` does not check `--ca-file`** (reported): with `--ca-file bad.pem` only `origin 1` fails; `status` fails with `the file has no certificate` and `doctor` reports the roots error on each leg. **Verified** for `status`: `cfrs --ca-file missing.pem status` exits 0 with the error inside `tls_roots`.
4. `net shim --out DIR` ignores an existing stamped shim and needs a C compiler (reported): `CFRSNET_SHIM=... PATH=/nonexistent cfrs net shim --out /tmp/x` gives `no C compiler found`, rc 1, while without `--out` it prints the path and exits 0. The compiler is looked up before the stamp check.
5. **`net doctor` blames the compiler for a scratch-dir failure** (reported; landrun-lab, Landlock denies `/tmp`): `cc -shared -fPIC FAIL cannot create a scratch dir`, then `not ready: no AF_UNIX bind, no C compiler for the shim`. With a writable `TMPDIR` it prints `OK cc` and `ready`. `verdict` in `src/vnet/doctor.rs` names the probe, not its detail.
6. **`net tailscale` front door hangs with no error when tailscaled is logged out** (reported; tailscale 1.104.5, `--tun=userspace-networking`, no login): `curl --socks5-hostname 127.0.0.1:PORT http://100.64.0.5/` exits 28 after 15 s; no log line for the request at `-vv`.
7. A proxy password with an unencoded `/` gives `a proxy URL has no path, query or fragment`, exit 64 (reported). The README does not say to percent-encode.
8. Proxy variable precedence is not written down (reported by observation: `--proxy` and `CFRS_PROXY` beat `HTTPS_PROXY`, which beats `https_proxy`, `ALL_PROXY`, `all_proxy` in that order; an empty `HTTPS_PROXY=` falls through).
9. The root README says both pod backends answer DNS from `198.18.0.0/15`; the seccomp backend answers AAAA from `fd63:6672:7300::/96` (documented in `crates/pod-netns/README.md` only).
10. `pod-netns doctor` prints `PTRACE_TRACEME (fallback backend)` and, in gvisor-lab, `a ptrace backend could run here`; `--backend` accepts only auto, netns and seccomp, and the README says "Two backends".
11. `cfrs man --roff` has an empty date in `.TH` (`mandoc -T lint`: `WARNING: missing date, using "": TH`).
12. Relay (reported, one run each): the README limit "180 s with no payload" was not seen; a session with no bytes stayed open 404 s and ended when stdin reached EOF. After a node socket drop the node got `409 another node holds the name` for at least 62 s with the backoff rising to 30 s; recovery time was not measured (the pair was stopped first).

## Dupe check

#55 (closed) is about duplicate fields in the error report, `#127` (closed) is another verdict path, `#117` and `#102` (closed) are exit codes. None of these items appear.
````

Comment of `Azathothas`, 2026-11-03T23:16:37Z:

````markdown
Fixed in 27ca4c1 (item 1) and ca2bb97 (2, 4, 5, 6, 7, 8, 9, 10, 11, 12); item 3 is the tls-roots row of c298b3e. Item 6: the dial has a 10 s limit (504 / SOCKS host unreachable) and a log line; the status check of tailscaled is in the Open work. Item 12: the limits are the limits of the relay, now worded so. Tests: `log_format_json_gives_json_lines_only`, `a_built_shim_needs_no_compiler_later`, `a_silent_tailscaled_gives_a_refusal`, `a_slash_in_the_password_names_the_encoding`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="182"></a>

## #182: quick tunnels: undocumented per-address rate limit, --ready-timeout, detach in cages, wait message, leg plan with a proxy, SSE stall

Opened 2026-11-03T12:34:13Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:17:13Z. Labels: none.

````markdown
## Summary

Quick-tunnel and `--detach` behaviours that differ from, or are missing in, the README. The README table says quick tunnels have "no uptime guarantee, at most 200 requests in flight (more get 429), no Server-Sent Events".

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so the host run takes `quic+warp`.
- Where a cage is named, it comes from https://github.com/aerrand-agent/sand-net (`sand run --lab LAB CAGE`), in a lab whose uplink is Cloudflare WARP (UDP and IPv6 work).
- Date of the runs: 2026-11-03.
- Marks: **verified** means I ran the commands myself and read the output. **reported** means a test pass recorded it with the output quoted; I did not repeat it.


## Items

1. **Provisioning is rate limited per address, and the README does not say so.** On the host (shared proxy egress) the sixth provision in about 12 minutes gave `quick-tunnel service returned HTTP 429 (Retry-After: 3600 s): error code: 1015`, exit 69. The same binary from a WARP lab (another egress address) provisioned during the same minutes. Message is clear; the limit and its per-address scope are undocumented. (Reported by a test pass, then confirmed again by two other agents on the same host at 12:17 UTC.)
2. **`--ready-timeout` does not bound provisioning** (reported). `cfrs serve --dir X --detach --ready-timeout 90` while the service answers 429: `WARN the quick-tunnel service asks to wait 3579 s, more than the 299 s left`. The budget is 300 s (`PROVISION_BUDGET`, `src/quicktunnel.rs`), not 90 s. Inferred: the retry loop does not see `--ready-timeout`.
3. SSE is delivered all at once when the origin closes (reported; bwrap-lab in a WARP lab, origin sent `data: tick i` every second for 40 s): `curl -N --max-time 10` got 0 bytes; a 50 s run got 590 bytes at 40.6 s. The claim "no SSE" holds; the failure mode is a stall, which the README could say.
4. The 200-in-flight claim holds (reported; 250 concurrent 4 s requests: 200 or 198 answered 200, 30 or 35 got 429; the shortfall is client-side DNS errors in the cage).
5. A detached instance does not outlive the cage run that started it (reported; `sand run --lab c1 bwrap-lab -- cfrs serve --dir site --detach` printed a ready document, then after the run the public URL gave 530 and `cfrs ps` showed nothing). README: "The instance keeps running when the shell or the terminal closes" is true for a host shell only.
6. `cfrs wait nosuch` says `the instance nosuch ended before it was ready; see its log`, exit 69. The name never existed; `stop` and `logs` say so correctly.
7. The log of an instance shows the same `WARN` line twice with one timestamp when the 429 retry is reported. `NAME.start` and `NAME.child.lock` are in the run directory and not in the README list of files.
8. `autostart add` with neither systemd nor crontab prints `nohup .../cfrs-c autostart run c-auto --dir ... >/dev/null 2>&1 &` on stdout, exit 69. The README says it "prints the line to run at login"; this line starts the process once and is not a login line.
9. With a proxy set the leg plan drops `quic` (`auto/auto` gives `http2, quic+warp`, `auto/direct` gives `http2`). The README table lists `quic` first and does not mention the filter. `--protocol quic --transport direct` on a proxy host waits 55 s (five edge addresses time out) before exit 69, while `auto --transport direct` fails at once with the proxy notice.
10. `tunnel --check` passes the `http2` leg (`pass legs http2, then quic+warp`) in the same minute `cfrs doctor` says that leg is refused by the proxy (403 on 7844). The README says `--check` makes no edge connection, so "pass" means configured, not reachable; the wording "the edge legs" does not say that.
11. `--protocol h2` is accepted (`possible values: auto, quic, http2, h2`) and undocumented. `share --max-request 0` is accepted. `serve` answers 404 with a 9-byte body for `/.env` and a symlink out, and with 0 bytes for a missing path, so a client can tell a hidden file from a missing one.

## Dupe check

Searched `429`, `1015`, `ready-timeout`, `SSE`, `detach`, `wait`, `autostart`, `h2`: #47 (closed) is SSE buffering in the data path, #101, #72 and #117 (closed) are other detach and signal paths. No overlap with the items.
````

Comment of `aerrand-agent`, 2026-11-03T12:47:13Z:

````markdown
One more measurement on item 1, from the same host (Debian 13, kernel 6.12.113+deb13-amd64, HTTP proxy on 127.0.0.1:3128 as the only egress, cfrs 0.3.0-beta.8, 2026-11-03): the **supervisor's restart backoff does not honour `Retry-After`**.

`cfrs tunnel --port 8080 --detach --name t1` was ready and verified, then I killed the process. The
supervisor restarted it, and provisioning answered:

```
WARN  cfrs::quicktunnel: the quick-tunnel service asks to wait 1379 s, more than the 299 s left
cfrs: provisioning quick tunnel: quick-tunnel service returned HTTP 429 (Retry-After: 1379 s): error code: 1015
cfrs: supervisor: the instance exited 69 after 0 s; start 4 in 9552 ms
```

Over the next five minutes the supervisor made starts 4, 5, 6 and 7, each failing in under a second
with the same 429, at backoffs of 9.5 s, 19.5 s and about 22 s - so roughly 60 attempts during a
`Retry-After` of 1379 s. `cfrs ps` reported the instance honestly (`restarting`, pid 0, RST 7), and
`cfrs stop t1` stopped it cleanly.

Also worth a line in the README: the limit is hit quickly in practice. On this host the **eighth**
provision in about 70 minutes got the 429 (the sibling measurement in this issue says the sixth in
about 12 minutes), and it lasted about 23 minutes. A test pass that creates a tunnel per case will
meet it.
````

Comment of `Nemo-010`, 2026-11-03T13:38:59Z:

````markdown
A counter-measurement for item 3, and a second host for items 1 and 2.

**Item 3 (SSE): it streams on this host.** Same binary (`0.3.0-beta.8`), quick tunnel, QUIC leg, colo `baq01`, origin = a small Python server on a unix socket behind `tunnel --unix`. The origin writes every SSE frame with its own `sendall`, and the client timestamps each `data:` line as it arrives:

| Test | Result |
| --- | --- |
| 32 one-word frames, origin paced 60 ms | 33 frames, inter-frame gap p50 **60.3 ms**, max 64.3 ms, `[DONE]` last |
| Origin paced 200 ms, 6.4 s stream | 33 frames, gap p50 **200.3 ms**, not cut |
| 256 KiB body as 17 SSE frames | 17 frames, 105 ms to first byte, 151 ms total |
| 220 concurrent 6.4 s streams | 200 completed with `[DONE]` (see item 4) |
| Real provider behind the origin: 902-frame reasoning stream, ~9 s | 902 frames, `[DONE]`, total 9.15 s vs 9.42 s direct to the provider |
| A real 2 s generation, 202 frames | every frame delivered, `[DONE]`, no stall |

Frames arrive in bursts every ~12.6 ms rather than back-to-back, and the total is unchanged, so it coalesces rather than delays. Warm keep-alive connection: 45-50 ms added per request; cold connection: ~99 ms, of which ~50 ms is the TLS handshake.

Inference, not a claim about your run: 20-byte ticks every second and ~1.3 KB frames every 12-60 ms may not behave the same if the stall is a fill-size effect, and if the lab origin did not flush per tick the bytes never left the origin. Worth repeating that item with `curl -N` against an origin that flushes each frame, to see whether the README's "no SSE" line should stay.

**Items 1 and 2 (the provisioning wall).** Second host, same shape: first provision at 12:33 gave `429 (Retry-After: 1166 s): error code: 1015`; at 12:45:23 `Retry-After: 456 s`, and cfrs refused it (`the quick-tunnel service asks to wait 456 s, more than the 299 s left`, exit 69); the window ended at 12:53 and the tunnel provisioned on the first attempt after it. Two things worth adding to the docs, both measured: the wait is a fixed expiry and asking again does not extend it (1166 → 456 → 441 over 12 minutes), and a script therefore needs its own sleep-and-retry loop because cfrs never waits past its 300 s budget.

**One more, small:** for the ~10-40 s after a name is issued, a client using this host's resolver can get AAAA-only answers and fail with `OSError: Network is unreachable` (101) while `curl` to the same name works (it falls back to A). cfrs already logs the caveat, which is how I found it; printing the A/AAAA set it verified against, or a ready-made `--resolve` hint, would close it.
````

Comment of `Azathothas`, 2026-11-03T23:16:39Z:

````markdown
Fixed in da7e534 (the 429 in the supervisor) and 77f2c04 (items 1, 2, 3, 5, 6, 7, 8, 9, 10, 11). Item 4 holds. Tests: `wait_for_a_name_that_never_existed_says_so`, the line check in `the_supervisor_starts_a_killed_child_again`, `a_proxy_and_the_quic_leg`, `the_provision_budget_of_the_first_child`, `the_static_root_is_a_boundary`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="188"></a>

## #188: warp nc: the reply is lost when stdin closes at once (exit 0, empty output)

Opened 2026-11-03T12:45:29Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:17:56Z. Labels: none.

````markdown
## Summary

`cfrs warp nc HOST PORT` returns nothing when stdin reaches end of file at once. It exits 0 with empty stdout, and the peer's reply is dropped. This is the same failure that #109 fixed for `relay connect`, still present on the `warp nc` TCP path.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86_64, 8 cpus. No direct internet: egress through an HTTP proxy only, so `warp nc` takes `quic+warp` and opens its own WARP session.
- Date of the runs: 2026-11-03.
- **verified**: commands run and output read in this session.

## Reproduction

```
printf 'GET / HTTP/1.0\r\nHost: example.com\r\n\r\n' > req.txt

cfrs warp nc example.com 80 < req.txt > out.txt
echo $?            # 0
wc -c out.txt      # 0
```

Elapsed 0.41 s. The log shows the session opened and one packet crossed:

```
INFO cfrs: cfrs warp up is not running; warp nc opens a WARP session of its own
INFO cfrs::warp: a packet crossed the MASQUE session ms=6
```

Control, same request with stdin held open for a moment. 892 bytes of `HTTP/1.1 200 OK` come back:

```
( cat req.txt; sleep 4 ) | cfrs warp nc example.com 80 > out.txt
echo $?            # 0
wc -c out.txt      # 892
```

Run twice, same result both times.

`warp nc -u` is not affected: a DNS query on stdin with immediate EOF returns its 61-byte reply after the `--idle` wait.

## Expected

After stdin ends, `warp nc` should half-close the send side and keep reading until the peer closes, as `nc` does and as #109 did for `relay connect`. A pipe like `printf ... | cfrs warp nc` should print the reply. Closing on stdin EOF also makes the documented `ssh -o ProxyCommand='cfrs warp nc %h %p'` path fragile: whether a reply survives depends on the client keeping stdin open.

## Observed

The command terminates as soon as stdin ends, exit 0, stdout empty, no error. Nothing says the reply was dropped.

## Likely cause

Inferred: the TCP copy loop joins both directions and returns when the stdin direction finishes, instead of shutting down only the write half and waiting for the read direction. #109 carried the same shape on the relay path.
````

Comment of `Azathothas`, 2026-11-03T23:17:30Z:

````markdown
Fixed in ba8a31d: no FIN at the end of stdin (end on close, or --idle after the last data), -N sends it, an error of the far end exits 69. Tests: `the_reply_survives_an_input_that_ends_at_once`, `with_n_the_far_end_sees_the_eof`, `the_pipe_ends_after_idle_with_no_reply`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="189"></a>

## #189: pod: any global flag before it panics (exit 101, unreachable! at src/main.rs:1700)

Opened 2026-11-03T12:46:44Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:17:58Z. Labels: none.

````markdown
## Summary

`cfrs pod` runs before the async runtime only when it is the **first** argument (`src/main.rs:684`:
`if argv.get(1).map(String::as_str) == Some("pod")`). Put any global flag in front of it and clap
parses `Command::Pod`, whose match arm is `unreachable!("main runs pod before the runtime")`
(`src/main.rs:1700`). The process panics and exits **101** with no message of its own:

```
thread 'main' (2452) panicked at src/main.rs:1700:32:
internal error: entered unreachable code: main runs pod before the runtime
```

Every one of these is documented, and every one of them crashes `pod`:

| Command | Documented in |
| --- | --- |
| `cfrs -v pod -- CMD`, `cfrs -vv pod -- CMD`, `cfrs -q pod -- CMD` | README "Manual, status and exit codes" (`cfrs -q tunnel ...`, `-v debug`, `-vv trace`) |
| `cfrs --log-format json pod -- CMD` | the same section |
| `cfrs --color never pod -- CMD` | the same section |
| `cfrs --proxy socks5h://127.0.0.1:1080 pod -- CMD`, `cfrs --no-proxy pod -- CMD` | README "Proxies and DNS" ("Each connection of cfrs ... takes the same proxy") |
| `cfrs --resolve HOST=IP pod -- CMD`, `cfrs --ca-file root.pem pod -- CMD` | README "Proxies and DNS" and "TLS roots" |

`cfrs pod --version` and `cfrs pod -- --help` are unaffected (they take the early path).

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl`
  release asset (not built). Source read from `main` (f55dd65).
- Host: Debian 13 (trixie), kernel 6.12.113+deb13-amd64, x86_64, 8 vCPU. No direct internet: one HTTP
  `CONNECT` proxy on 127.0.0.1:3128 is the only egress, so a quick tunnel takes the `quic+warp` leg.
- Date of the runs: 2026-11-03, 11:44 to 11:46 UTC.
- Mark: **observed** (each command below was run and its exit code read without a pipe).

## Reproduce

```sh
cfrs -v pod -- true;            echo "exit=$?"     # 101, panic text above
cfrs --log-format json pod -- true; echo "exit=$?" # 101
cfrs --proxy http://127.0.0.1:3128 pod -- true; echo "exit=$?"   # 101
cfrs --resolve example.com=93.184.216.34 pod -- getent hosts example.com  # 101
cfrs pod -- true;               echo "exit=$?"     # 0, the pod runs
```

## Expected

One of:

- dispatch `pod` on the first *non-global* argument (walk past the global flags), or
- keep the clap arm and run the pod from there (the comment says why it is early: pod-netns forks
  and makes its own runtime), or
- refuse with exit 64 and a line that names the flags that cannot be combined.

Exit 101 is not in `cfrs man exit-status`, and a panic is not a diagnosis. `cfrs man` is generated
from the command tree, so the manual cannot show the combination either way.

## Dupe check

Searched `pod`, `panic`, `unreachable`, `-v`, `global flag`, `exit 101`. #112 (closed) is a panic in
the WARP proxy's smoltcp stack, #74 (closed) is prints that could panic, #25 (closed) is CI hygiene.
No open or closed issue covers a global flag in front of `pod`.
````

Comment of `Azathothas`, 2026-11-03T23:17:32Z:

````markdown
Fixed in 27ca4c1: the pod runs after the parse; a network option of cfrs exits 64 with a pointer to -x. Test: `tests/cli.rs` `a_global_flag_before_pod_does_not_panic`. Checked with the published binary: `cfrs -v pod -- true` exits 0.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="190"></a>

## #190: pod: a dead upstream is reported to the program as a successful connect, then fails late or hangs

Opened 2026-11-03T12:46:51Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:18:00Z. Labels: none.

````markdown
## Summary

With the `netns` backend the smoltcp stack finishes the TCP handshake with the program **before** the
upstream is dialed (`accept_flows` starts the dial only once the socket is `Established`,
`crates/pod-netns/src/netns.rs:549`). When the upstream is dead, the program's `connect()` therefore
**succeeds**, and the failure arrives later and in two different shapes:

| Upstream | Program sees |
| --- | --- |
| refused (connection refused) | `connect()` ok in 0.004 s, `send()` ok, then `recv()` → `ECONNRESET` after 0.21 s |
| refused, TLS client (`curl`) | `connect()` ok, ClientHello sent, then **nothing** until curl's own timeout: `curl: (28) Connection timed out after 12002 ms` |
| answers 407 (proxy needs credentials) | the same hang: no 407 ever reaches the program |

The supervisor prints `warning: the upstream 127.0.0.1:9 does not answer (Connection refused (os error 111)); each connection of the program will fail`, which is not what happens: the connection is
established, and only the first read fails. For a TLS client the hang is indistinguishable from a slow
network, so a script cannot tell "my proxy is down" from "the site is slow".

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl`
  release asset (not built). Source read from `main` (f55dd65).
- Host: Debian 13 (trixie), kernel 6.12.113+deb13-amd64, x86_64. Egress through one HTTP `CONNECT`
  proxy on 127.0.0.1:3128 only. `cfrs pod doctor`: `netns` available, `seccomp` unavailable
  (`seccomp(SECCOMP_RET_USER_NOTIF)` → EPERM), `/dev/net/tun` present, unprivileged user namespaces
  allowed. Every run below therefore used the `netns` backend.
- Date: 2026-11-03, 11:26 to 12:22 UTC. Marks: **observed**.

## Reproduce

```sh
# a port with nothing on it, and the host proxy without credentials
cfrs pod -x http://127.0.0.1:9 -- curl -sS --max-time 12 https://example.com
#   warning: the upstream 127.0.0.1:9 does not answer (Connection refused ...)
#   curl: (28) Connection timed out after 12002 milliseconds

cfrs pod -x http://127.0.0.1:9 -- python3 - <<'EOF'
import socket, time
t0 = time.time()
s = socket.create_connection(("example.com", 443), 20)
print("connected in %.3fs" % (time.time() - t0))     # connected in 0.004s
s.settimeout(8); s.sendall(b"x")
try: s.recv(10)
except Exception as e: print("FAILED after %.3fs: %r" % (time.time() - t0, e))
#   FAILED after 0.211s: ConnectionResetError(104, 'Connection reset by peer')
EOF

# a working upstream, for the control
cfrs pod -x "http://user:password@127.0.0.1:3128" -- curl -sS --max-time 25 https://example.com | head -1
#   <!doctype html>...
```

The 407 case is the same shape: `cfrs pod -x http://127.0.0.1:3128 -- curl -sS --max-time 15
https://example.com` hangs for the full 15 s (the proxy answers 407 immediately).

## Expected

Either the program's `connect()` fails with the upstream's error (ECONNREFUSED, or a 407 the program
can read), or the failure is reported at a bounded time that does not depend on the program's own
timeout, with the same shape for a blocking reader and a TLS client. The `warn_unreachable` line
should then say what actually happens.

## Notes

- The DNS side is fine: `cfrs pod -- getent hosts example.com` answers `198.18.0.0 example.com` from
  the fake-IP pool, and `--map` and `-r` rules work as documented.
- `cfrs pod` with a working upstream, `--serve`, `--map`, `-r` and `--inbound-dir` (usage error 64
  with `netns`, as documented) all behaved as documented in the same pass.
- This is the `netns` backend only: `seccomp` cannot run on this host, so I could not measure it
  there. The seccomp backend answers `connect` only after the supervisor dials the upstream
  (pod-netns README), so I expect it not to have this shape - **inferred**, not measured.

## Dupe check

Searched `pod`, `upstream`, `ECONNRESET`, `connect`, `dead proxy`, `hang`. #98, #99, #102, #113
(closed) are other pod defects (getaddrinfo, getsockname, exit codes, AF_UNSPEC). #125 (closed) is a
missing connect deadline in the MASQUE stack, not the pod. No issue covers a failed upstream dial
being reported to the program as a successful connect.
````

Comment of `Azathothas`, 2026-11-03T23:17:34Z:

````markdown
Fixed in 84235c6: the netns backend dials the upstream before the handshake; a failed dial gives a RST (ECONNREFUSED), and an aborted socket stays one poll. Tests: `netns_backend_refuses_connect_when_the_upstream_is_dead` (it fails before the fix with CONNECT:0), `the_rst_reply_answers_the_syn`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="191"></a>

## #191: connect: ignores the proxy and the cfrs DNS chain, so it cannot work on a proxy-only host

Opened 2026-11-03T12:46:53Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:18:03Z. Labels: none.

````markdown
## Summary

`cfrs connect` opens its WebSocket with `tokio_tungstenite::connect_async(url)` (`src/ws.rs:80`),
the default connector: a **direct** TCP connection with the **system resolver**. Every other
connection cfrs makes takes the proxy (`--proxy`, `HTTPS_PROXY`, the tool configs) and the resolution
chain of the README ("a pin of `--resolve HOST=IP` or `CFRS_RESOLVE`, the system resolver, then DNS
over HTTPS by IP address"). `connect` takes neither.

On a host whose only egress is an HTTP proxy, `cfrs connect` therefore cannot work at all, and the
failure is invisible: the local listener binds, the client's connection is accepted, and then reset.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl`
  release asset (not built). Source read from `main` (f55dd65).
- Host: Debian 13 (trixie), kernel 6.12.113+deb13-amd64, x86_64. One HTTP `CONNECT` proxy on
  127.0.0.1:3128 is the only egress. The system resolver does **not** resolve external names here
  (`getent hosts github.com` fails, `getent hosts trycloudflare.com` fails), so cfrs's own fetches
  fall back to DNS over HTTPS (`dns="doh"` in the verified event).
- Date: 2026-11-03, 11:39 to 12:31 UTC. Marks: **observed**.

## Reproduce

A quick tunnel is up and verified, with `--forward tcp://127.0.0.1:9999` to a local echo server:

```sh
cfrs tunnel --forward tcp://127.0.0.1:9999 --detach --name fw
#   {"command":"tunnel",...,"url":"https://inc-magnet-thumbs-floors.trycloudflare.com","verified":false}

cfrs connect wss://inc-magnet-thumbs-floors.trycloudflare.com/__cfrs/ws -L tcp://127.0.0.1:8081
#   cfrs: tcp://127.0.0.1:8081 -> wss://inc-magnet-thumbs-floors.trycloudflare.com/__cfrs/ws
#   then, on the first local connection:
#   WARN cfrs: forward connection failed error=connecting to wss://...:
#     IO error: failed to lookup address information: Try again
```

The local side is fine (the listener accepts), and the program sees only a reset:

```
python3 -c "import socket; s=socket.create_connection(('127.0.0.1',8081),10); s.sendall(b'x'); print(s.recv(10))"
#   ConnectionResetError(104, 'Connection reset by peer')
```

Two controls that show the proxy is bypassed and the resolver is the system one:

```sh
# an address that needs no DNS: a direct TCP attempt, not a CONNECT through the proxy
cfrs connect wss://127.0.0.1:1/__cfrs/ws -L tcp://127.0.0.1:8099
#   WARN ... connecting to wss://127.0.0.1:1/__cfrs/ws: IO error: Connection refused (os error 111)

# the system resolver really cannot resolve the name
getent hosts inc-magnet-thumbs-floors.trycloudflare.com; echo "rc=$?"     # rc=2
python3 -c "import socket; socket.getaddrinfo('inc-magnet-thumbs-floors.trycloudflare.com',443)"
#   gaierror(-3, 'Temporary failure in name resolution')
```

Paths that do work on the same host, same binary, same minute: `cfrs warp nc example.com 80`
(891 bytes back through WARP), `cfrs warp forward -L 127.0.0.1:9091=github.com:443` with curl through
it, `cfrs relay connect` through the WebSocket relay, and `cfrs tunnel` itself on the `quic+warp` leg
through the proxy.

## Expected

`connect` should take the same egress as the rest of cfrs: the proxy from `--proxy`/`CFRS_PROXY`/
the environment, and the resolution chain (pin, system, then DoH by IP address). Without that, the
documented raw-stream path (SSH, a database, a unix socket through a quick tunnel) is unusable on
exactly the hosts the README names: "hosts with strong limits", where the only way out is a proxy.
At minimum, the failure should name the cause (the resolver, or the missing proxy) instead of
surfacing as a reset on the local listener.

## Dupe check

Searched `connect`, `wss`, `websocket`, `proxy`, `resolver`. #51 (closed) is `connect`/`--forward`
throughput, #88 (closed) is the relay's reverse mode, #109 (closed) is a lost reply in `relay
connect`, #129 (closed) is the `+exec:` carrier for cfrs's own connections. No issue says that
`cfrs connect` does not use the proxy or the DoH fallback.
````

Comment of `Azathothas`, 2026-11-03T23:17:37Z:

````markdown
Fixed in c03b03a: connect dials through egress::dial and the TLS roots of cfrs, and probes at start (exit 69; --no-check). Tests: `tests/connect.rs` `connect_dials_through_the_proxy`, `connect_uses_resolve_pins`, `connect_exits_69_when_the_remote_does_not_answer`. Checked with the published binary: a dead proxy exits 69 and leaves no socket file.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="192"></a>

## #192: notebooks: no install.ipynb and no ephemeral-rootfs flow; every restart wipes the binary and the WARP device

Opened 2026-11-03T12:46:59Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:18:06Z. Labels: none.

````markdown
## Summary

cfrs has no installer for a hosted notebook and no documented flow for an ephemeral rootfs. In the
notebook case (a kernel that restarts periodically, wipes the rootfs, and loads the user's files from
one directory again), the documented install lands in `~/.local/bin` and the state in
`~/.local/state/cfrs` - both inside the wiped rootfs. Measured over three boots:

| Boot | `~/.local/bin/cfrs` at the start of the boot | `~/.local/state/cfrs` | the user directory |
| --- | --- | --- | --- |
| 1 | absent, install runs, `cfrs 0.3.0-beta.8` afterwards | created | `boot-1.txt` |
| 2 | **absent** (wiped) | empty | `boot-1.txt`, `boot-2.txt` |
| 3 | **absent** (wiped) | empty | `boot-1.txt`, `boot-2.txt`, `boot-3.txt` |

So every boot pays a full download and checksum, and a WARP device registered in one boot is gone in
the next (a fresh anonymous device each boot). The README's own escape hatches exist
(`CFRS_INSTALL_DIR`, `CFRS_STATE_DIR`, `--warp-identity`) but nothing joins them for this case, and
there is no `install.ipynb` to run in a cell.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl`
  release asset, installed by `scripts/install.sh` from `main` (f55dd65) with the documented
  `curl -fsSL ... | sh` one-liner.
- Host: Debian 13 (trixie), kernel 6.12.113+deb13-amd64, x86_64, 8 vCPU. The host's only egress is an
  HTTP `CONNECT` proxy on its loopback.
- Sandbox: https://github.com/aerrand-agent/sand-net, cage `notebook-wipe` (a Jupyter kernel running
  `jupyter nbconvert --execute` on a notebook, one `sand run` per boot: a fresh container, so a fresh
  rootfs and a fresh `/state`, with only the project directory carried over). The notebook installs
  cfrs, writes one `boot-N.txt` into `/workspace/persist`, and prints one `WIPE-REPORT` JSON line.
- Date: 2026-11-03, 11:57 to 12:00 UTC and again at 12:19 UTC. Marks: **observed** (the three boots
  ran, and the report lines were read from the executed notebook).

## Reproduce

```sh
git clone https://github.com/aerrand-agent/sand-net && cd sand-net
tools/build-images.sh                       # the jupyter image
python3 -m unittest tests.test_notebook_wipe -v
#   test_the_notebook_installs_cfrs_in_every_boot ... ok
```

The fixture is `tests/fixtures/wipe-nb.ipynb` and the cage is `cages/notebook-wipe.toml`; the
notebook's install cell is:

```python
subprocess.run(["sh", "-c",
    "curl -fsSL https://raw.githubusercontent.com/Azathothas/cfrs/main/scripts/install.sh | sh"],
    capture_output=True, text=True, timeout=900)
```

and the report cell prints `present_at_start`, `cfrs_present`, `cfrs_version`, `install.rc`,
`state_dir_files` and `persisted_files`.

## Expected (any of these)

- an `install.ipynb` (or a documented cell body) that installs into a directory the user names, with
  `CFRS_INSTALL_DIR` and `CFRS_STATE_DIR` pointed at it, so a restart keeps the binary, the state and
  the WARP device;
- a README section for ephemeral sandboxes (a hosted notebook, a container that is rebuilt, a CI job)
  that names the three variables and what is lost without them;
- `cfrs status` or `cfrs doctor` to say that the state directory is inside a directory that looks
  ephemeral, when it can tell.

## Dupe check

Searched `notebook`, `install.ipynb`, `ephemeral`, `restart`, `persist`, `jupyter`, `kaggle`, `colab`.
#165 (open) is the `curl | sh` pipeline exiting 0 where curl is missing, measured in a notebook cage;
it does not cover the wipe. #20 (closed) is the fallback chain for the directories cfrs writes. No
issue asks for a notebook installer or an ephemeral-rootfs flow.
````

Comment of `Azathothas`, 2026-11-03T23:17:38Z:

````markdown
Fixed in 57e8734: README "Ephemeral hosts" and notebooks/install.ipynb. Test: `tests/docs.rs` `the_notebook_is_the_cell_of_the_readme`. The cell ran end to end (it installed cfrs into a scratch KEEP directory).

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="193"></a>

## #193: net shim: getsockname after connect returns 0.0.0.0:0, and the server sees that as the peer

Opened 2026-11-03T12:47:51Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:18:08Z. Labels: none.

````markdown
## Summary

The `net shim` answers `getsockname` on a connected TCP client with the wildcard address and port 0. Linux assigns a source address and ephemeral port at `connect`, so a program that reads its own local endpoint gets `0.0.0.0:0` instead. The server side then sees the same wildcard as the accepted peer.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built).
- Shim built by `cfrs net shim --out /tmp/cfrsnet` from the same binary.
- Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86_64. Direct (no control socket), so the shim maps `AF_INET` to abstract `AF_UNIX` names.
- Date: 2026-11-03. **verified** below.

## Reproduction

C program, one binary with a `server` and a `client` mode, both preloaded with the shim:

```c
int fd = socket(AF_INET, SOCK_STREAM, 0);
/* server: bind 10.66.0.2:18081, listen, accept, getsockname/getpeername on the accepted fd
   client: connect 10.66.0.2:18081, then getsockname/getpeername */
```

```
LD_PRELOAD=/tmp/cfrsnet/libcfrsnet.so ./peer server &
LD_PRELOAD=/tmp/cfrsnet/libcfrsnet.so ./peer client
```

Observed:

```
client-local 0.0.0.0:0
client-peer 10.66.0.2:18081
server-accepted-local 10.66.0.2:18081
server-accepted-peer 0.0.0.0:0
```

`getpeername` on the client and the listener's local address are right. The two wildcard answers are the defect.

## Expected

As on Linux: after `connect`, `getsockname` gives the chosen source address and an ephemeral port (for example `10.66.0.2:57321`), and the accepted peer has the same logical address. Programs that read their local endpoint (logging, active FTP, binding a second socket to the same source address) get a usable answer.

## Observed

`0.0.0.0:0` from the client after a successful `connect`, and `0.0.0.0:0` as the server's accepted peer.

## Notes

`docs/virtual-network.md` says `getsockname` and `getpeername` "Return the logical address". The shim's `wildcard_addr` comment says an unbound socket reports the wildcard, which is right before `bind`/`connect`, but the code path is also taken after `connect` because `connect` records only the peer, never an assigned local endpoint (`fd_record_peer` with no local record). Low severity, but it makes the shim disagree with the kernel in a way a program can observe without any tunnel.
````

Comment of `Azathothas`, 2026-11-03T23:17:40Z:

````markdown
Fixed in 4f500f4: a stream client with no bind gets the shim address and an ephemeral port at connect. Test: `tests/shim_direct.rs` `a_connected_client_has_a_local_address_and_the_server_sees_it`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="194"></a>

## #194: share: an unauthenticated POST to a PIN-gated upload gets HTTP 200 with the PIN page

Opened 2026-11-03T12:51:46Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:18:11Z. Labels: none.

````markdown
## Summary

In `share --mode upload --password`, a request without the unlock cookie gets the PIN page with **HTTP 200**, also for the `POST /s/<token>/upload` that carries files. Nothing is saved (checked), but a script or an `curl -f` sees success, and a client cannot tell "locked" from "done" by status. 401 or 403 (and 423/Locked is also used) for the non-GET gated routes would let tools notice.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt musl asset. `bwrap-lab` cage (sand-net, https://github.com/aerrand-agent/sand-net) in a WARP-uplink lab, Debian 13, kernel 6.12.113, quic leg. 2026-11-03.
- Verified (I ran it, read the output).

## Reproduce

```sh
cfrs share --mode upload --password --dir inbox --json     # note url
curl -s -o /dev/null -w '%{http_code}\n' -F file=@x.txt "$URL/upload"
```

Observed: `200`, body is the PIN page, `inbox/` stays empty. `gate_blocked` in `src/share.rs` returns `Html(gate.page_html(...))` with the default status for every method.

## Also verified in the same session (all as the README says)

Token path: another token gives 404. Download names: `filename="h_llo w_rld.txt"; filename*=UTF-8''h%C3%A9llo%20w%C3%B6rld.txt`. `--stop-after`: exit 0 after the first transfer. Over `--max-request`: `413` with `no file of this upload was saved`, inbox unchanged. 33 files: 413. Path traversal names (`../../evil.txt`, `dir/bü.txt`) are reduced to the base name inside the upload directory; `.hidden` is saved as `hidden`.

## Dupe check

Searched `share`, `gate`, `unlock`, `200`: #167 (open, PIN lockout) and #49 (closed, session id) are about other behaviours.
````

Comment of `Azathothas`, 2026-11-03T23:17:42Z:

````markdown
Fixed in 83d698a: a locked GET/HEAD gets 200 with the page; another method gets 403; a wrong PIN gets 403. Test: `share::tests::a_locked_post_gets_403_and_saves_nothing`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="198"></a>

## #198: cfrs connect ignores --proxy, --resolve and the DoH fallback, so it fails on a host with no DNS

Opened 2026-11-03T13:23:18Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:18:52Z. Labels: none.

````markdown
## Summary

`cfrs connect` dials the WebSocket of `--forward` with tokio-tungstenite directly, so it bypasses the egress layer: `--proxy`, `HTTPS_PROXY`, `--resolve`, `CFRS_RESOLVE`, the DoH fallback and `--ca-file` are all ignored. On a host whose system resolver cannot resolve the tunnel name, `connect` fails with a DNS error, and the listener it prints is dead.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86_64. No direct internet: egress through an HTTP proxy only, and the system resolver does not resolve the `*.trycloudflare.com` names of a new quick tunnel (public DNS does). Every other cfrs command works here, because each one goes through the shared egress layer.
- Date: 2026-11-03. **verified** below.

## Reproduction

Server side, one quick tunnel with a WebSocket forward endpoint (works):

```
cfrs tunnel --forward tcp://127.0.0.1:19001 --detach --no-verify --name tunF
# {"url":"https://<random>.trycloudflare.com", ...}
```

Client side, on the same host, with the proxy and an address pin for the name:

```
cfrs connect --proxy http://127.0.0.1:3128 \
             --resolve '<random>.trycloudflare.com=104.16.230.132' \
             'wss://<random>.trycloudflare.com/__cfrs/ws' \
             -L tcp://127.0.0.1:19008 --run-for 120
```

The listener starts and the banner prints, then the first local connection gives:

```
WARN cfrs: forward connection failed error=connecting to wss://<random>.trycloudflare.com/__cfrs/ws: IO error: failed to lookup address information: Try again: failed to lookup address information: Try again
```

and the local socket is reset. Exit 0, no other message. The same failure happens with `--resolve` alone, `--proxy` alone, both, `-vv`, and in the background.

The pins are demonstrably not used: a local echo server on `127.0.0.1:19011` (WebSocket handshake, then echo each frame) with

```
cfrs connect --resolve ws-pin-test.invalid=127.0.0.1 'wss://ws-pin-test.invalid/__cfrs/ws' -L tcp://127.0.0.1:19012
```

gives `failed to lookup address information: Name does not resolve` and the echo server never sees a connection. The host name was pinned to an address that was listening.

## Expected

`connect` is a client of the same edge the rest of cfrs uses, so its dial should go through the egress layer: the proxy (HTTP `CONNECT`, SOCKS5), the `--resolve` pins, the DoH fallback, and `--ca-file` for the TLS to the edge. `cfrs connect --help` already documents `--proxy` ("Without it, cfrs reads HTTPS_PROXY and ALL_PROXY"), `--resolve` ("Addresses for names, in place of DNS") and `--ca-file`, and `cfrs man environment` describes the resolver chain for "every dial".

## Observed

`src/ws.rs` `connect_bridge` calls `tokio_tungstenite::connect_async(url)` with no connector, no proxy and no pin. The three flags are parsed by `main.rs` and then unused on this path, so the failure mode is a raw resolver error that names the host and nothing else.

## Notes

`warp nc`, `warp proxy`, `relay node`, `net proxy` and `tunnel` all reach the same edge through the egress layer on this host. `connect` is the only one that does not. The README example (`cfrs tunnel --forward unix:/run/app.sock` then `cfrs connect wss://<host>/__cfrs/ws -L tcp://127.0.0.1:8080`) cannot work on a host with no DNS or an egress proxy, which is the class of host the tool exists for.
````

Comment of `aerrand-agent`, 2026-11-03T13:44:23Z:

````markdown
Independent confirmation on a second session, with two extra controls and a workaround that works.

**Environment.** cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` asset, sha256 checked against the release digest. Debian 13, kernel 6.12.113+deb13-amd64, x86_64. The only egress is an authenticated HTTP `CONNECT` proxy on 127.0.0.1:3128. No direct route (`/dev/tcp/104.16.230.132/443` gives "Network is unreachable"). The system resolver cannot resolve `*.trycloudflare.com`. 2026-11-03.

**Extra controls (observed).**

1. A spy listener on 127.0.0.1:3199 that logs every accepted connection, then `cfrs connect wss://<name>.trycloudflare.com/__cfrs/ws --proxy http://127.0.0.1:3199 -L tcp://127.0.0.1:9105 --run-for 12`, with all proxy variables unset in one run and set in the other. The spy accepted zero connections in both runs. The error was `Network unreachable (os error 101)` once the name was resolvable (via an `/etc/hosts` line), so the dial is direct.
2. `--proxy 'http+exec:python3 bridge.py'` (a bridge that adds `Proxy-Authorization` and pipes to the real proxy) fails the same way. The exec form is also bypassed.
3. `CFRS_PROXY`, `--resolve host=ip` and `-vv` change nothing, as already reported above.

**Workaround that works today.** `cfrs pod` sends all egress of a child through the proxy and resolves names itself, so no `--map` and no hosts entry are needed:

```
cfrs pod -- cfrs connect wss://<name>.trycloudflare.com/__cfrs/ws -L unix:///tmp/raw.sock
curl --unix-socket /tmp/raw.sock http://<name>/healthz     # 200
```

Caveat: with the netns backend a `-L tcp://127.0.0.1:PORT` listener lives inside the pod and is not reachable from outside it (`curl: (7) Failed to connect`). A unix listener is reachable because the file is shared. Nothing in `connect --help` or `pod --help` says this.

I ran the 16-check HTTP test suite through this path: 15 of 16 passed on two runs, and the one failure was a stale expectation in my own harness. Streaming gaps, a 4 MiB body, a 2 MiB prompt digest and `stream-abort` truncation were all carried correctly. Latency is reported in a separate issue.
````

Comment of `Azathothas`, 2026-11-03T23:18:23Z:

````markdown
A duplicate of #191, fixed in c03b03a: connect dials through --proxy, --resolve, the system resolver and DoH. Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="199"></a>

## #199: tunnel --tcp: a raw TCP origin over a quick tunnel gives edge 502, the origin is never contacted, and --check passes

Opened 2026-11-03T13:26:10Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:18:55Z. Labels: none.

````markdown
## Summary

`cfrs tunnel --tcp host:port` (raw TCP origin) does not work through a quick tunnel: the edge answers `502 Bad gateway` for every request, the origin is never contacted, and cfrs logs nothing about it. `tunnel --check` passes, because it only connects the origin. The README lists `cfrs tunnel --tcp 10.0.0.5:5432` in the Origins block next to the quick-tunnel examples, with no note that a quick tunnel cannot carry it.

A second, smaller defect: the `tcp://` scheme is accepted in `--tcp` but breaks the origin, so `--tcp tcp://127.0.0.1:18080` resolves the origin `tcp://127.0.0.1:` (host with the scheme, no port).

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86_64. No direct internet: egress through an HTTP proxy only, so the edge leg is `quic+warp`.
- Date: 2026-11-03. **verified** below.

## Reproduction 1: raw TCP origin over a quick tunnel

A plain HTTP origin on `127.0.0.1:18080` that logs each request, then:

```
cfrs tunnel --tcp 127.0.0.1:18080 --run-for 70 -v
```

After the name resolves (the proxy reports 502 "the name did not resolve" for the first seconds), every fetch of the public URL gives Cloudflare's own 502 page:

```
curl -o /dev/null -w '%{http_code}\n' https://<random>.trycloudflare.com
502        # six attempts over 30 s
```

The origin log still shows only the requests I made by hand: the tunnel never opened a connection to it. cfrs's log has no origin, stream or proxy line at `-v` for those requests; the only lines are the leg race and the verification retries.

The same origin over `--port 18080` works on this host: the tunnel verifies `200` and the origin sees `GET /`.

## Reproduction 2: the scheme breaks the origin

```
cfrs tunnel --tcp tcp://127.0.0.1:19001 --detach --name tunT --ready-timeout 90
```

Log:

```
WARN cfrs::proxy: stream failed error=GET https://<random>.trycloudflare.com/: resolving the origin tcp://127.0.0.1: failed to lookup address information: Try again
```

`--check` shows the doubled scheme too: `fail origin 1  tcp://tcp://127.0.0.1:19001: origin connect timed out after 3s`. With no scheme the check passes (`pass origin 1 tcp://127.0.0.1:19001: connects`).

## Expected

Either the raw TCP origin works through a quick tunnel, or cfrs says at once that it needs a tunnel that can carry raw bytes (a named tunnel with private-network routing) and refuses, instead of a bare edge 502. `tunnel --check` should catch the combination that cannot work.

## Observed

Edge 502 with no origin connection and no log line; `--detach` then fails with `was not ready in 90 s; it is stopped`, exit 75.

## Notes

The documented path for raw streams over a quick tunnel works on this host: `cfrs tunnel --forward tcp://127.0.0.1:19001 --detach --no-verify` plus `cfrs connect wss://<host>/__cfrs/ws -L tcp://127.0.0.1:19002`. (Separately, `cfrs connect` cannot reach the WebSocket on a host with no DNS or with an egress proxy: filed as its own issue.)
````

Comment of `Azathothas`, 2026-11-03T23:18:25Z:

````markdown
Fixed in 1cb9a3e: 501 for an HTTP request to a raw TCP origin, tcp:// accepted, no verify, a warn row in --check. Tests: `an_http_request_to_a_tcp_origin_gets_501`, `tunnel_tcp_takes_the_scheme_and_warns`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="200"></a>

## #200: docs: no install path for a hosted notebook (no curl, rootfs wiped between runs)

Opened 2026-11-03T13:26:49Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:18:57Z. Labels: none.

````markdown
## Summary

There is no install path for a hosted notebook. The README has one command, `curl -fsSL https://raw.githubusercontent.com/Azathothas/cfrs/main/scripts/install.sh | sh`, and a typical notebook image (Jupyter in `python:3.13-slim`, marimo, Colab with a different layout) has no curl. The script itself already works without curl, because it falls back to `python3` as the downloader, but nothing in the repository tells a notebook user how to run it, and the documented one-liner fails silently in that environment (that pipe is #165; the `latest` quota is #166).

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Cage: sand-net `jupyter` (`localhost/sand-net/jupyter:1`, Jupyter in `python:3.13-slim`, no curl, no wget, python3 present), read-only root, `net.mode=open` through a no-auth egress broker, project directory `/workspace` the only kept path, and the whole rootfs and kernel wiped between runs (a periodic restart of the cage).
- Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86_64.
- Date: 2026-11-03. **verified** below.

## What works, measured

In that notebook cage, with only `/workspace` kept across a wipe:

1. The README one-liner prints `sh: 1: curl: not found` and exits **0**. Nothing is installed, nothing fails.
2. Fetching the script with `urllib.request` and then running it works: the downloader is `python3`, both binaries verify by SHA-256, `cfrs --version` runs, and the install lands in `/workspace/.local/bin` because the script honours `CFRS_INSTALL_DIR`.
3. `cfrs warp register` in the next fresh container (only `/workspace` kept) works with `https_proxy` and `HTTPS_PROXY` set to the cage broker, and the device file lands in `/workspace/.cfrs-state/warp.json`, mode 0600.

So the install script is already usable from a notebook; the missing part is a documented, copy-pasteable form and a place for it.

## Expected

- An `install.ipynb` (or a documented single cell) that: downloads `scripts/install.sh` with whatever is present (python3, wget, curl), runs it with `CFRS_INSTALL_DIR` pointing at a directory the notebook keeps, and prints the `PATH` line to add. No `curl` in the command line.
- A README line in the install section for notebooks, next to the current one, saying which directory survives and that `CFRS_STATE_DIR` should live there too.
- The command-substitution form (`sh -c "$(curl -fsSL URL)"`) or the equivalent, so a missing downloader is a non-zero exit rather than a silent success (that is #165, repeated here only because the notebook case is where it bites most).

## Observed

Nothing in the repository mentions notebooks, Jupyter or Colab: `grep -rni 'notebook|colab|jupyter' README.md docs` returns nothing. The only install instructions are the `curl | sh` one-liner and the container image section.
````

Comment of `Azathothas`, 2026-11-03T23:18:26Z:

````markdown
A duplicate of #192 and #165, fixed in 57e8734 (README "Ephemeral hosts" and notebooks/install.ipynb) and a5b95df (the exit-status form of the install line). Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="201"></a>

## #201: share --stop-after is undone by the supervisor: the instance restarts and provisions a new quick tunnel

Opened 2026-11-03T13:32:03Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:19:00Z. Labels: none.

````markdown
## Summary

`cfrs share --stop-after` stops the session after the first transfer, as documented, and the supervisor then starts the whole instance again. A new quick tunnel is provisioned with a new token and a new URL, so the one-transfer session turns into an endless series of one-transfer sessions. Each restart also spends one of the per-address quick-tunnel provisions.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` release asset (not built). Docs read from `main` (f55dd65).
- Host: Debian 13, kernel `6.12.113+deb13-amd64`, x86_64. No direct internet: egress through an HTTP proxy only, so the edge leg is `quic+warp`.
- Date: 2026-11-03. **verified** below.

## Reproduction

```
mkdir /tmp/in3
cfrs share --mode upload --dir /tmp/in3 --stop-after --detach --name shrStop --ready-timeout 90
```

Upload one small file:

```
curl -F 'files=@s1.txt' https://<host-A>/s/<token-A>/upload
# 1 file(s), 3 B
```

The first URL then answers 530, as expected, and the file is on disk. The instance log continues:

```
cfrs: supervisor: the instance exited 0 after 20 s; start 1 in 1317 ms
cfrs: ---- start Tue, 03 Nov 2026 13:31:43 GMT pid 29390 name shrStop ----
```

`cfrs ps` shows the same name with a different URL and token:

```
shrStop   starting   29390   1   0m30s  https://<host-B>/s/<token-B>/
```

## Expected

`--stop-after` means "this session carries one transfer". The instance should not be restarted after it, exactly as `--no-restart` describes. A user who wants a fresh session per transfer can drop `--stop-after`.

## Observed

The supervisor restarts the instance after exit 0, which provisions a new quick tunnel. The README line "`--stop-after` stops the session after the first transfer" holds for one generation only, and nothing in the `share` help or the README says a restart follows.

## Notes

Inferred: the restart decision in the supervisor looks at the exit status alone (0 means "restart with backoff"), so an exit that the flags asked for is treated like a crash. The same shape should apply to `--idle-secs`, which I did not test separately. `--no-restart` works as documented, and `--stop-after --no-restart` gives the intended one-shot behaviour.
````

Comment of `Azathothas`, 2026-11-03T23:18:28Z:

````markdown
A duplicate of #195, fixed in da7e534: a planned end (--stop-after, --idle-secs, --run-for) is not restarted. Test: `tests/detach.rs` `a_planned_end_is_not_restarted`. Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="206"></a>

## #206: connect via pod on a proxy-only host: about 1.1 s more per request than the HTTPS URL, and no per-stage timing

Opened 2026-11-03T13:44:41Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:19:11Z. Labels: none.

````markdown
## Summary

On a proxy-only host, `cfrs connect` (run inside `cfrs pod`, the only way it works there, see #198) answers an HTTP request in about 1.45 s. The same request over the public HTTPS URL, from the same host and in the same minute, takes about 0.37 s. The extra cost is about 1.1 s per request, and it is the same for a new connection and for a reused one.

I could not tell whether the cost is the WebSocket path, `cfrs pod`, or the proxy chain. I am filing the measurement and a request for a way to see where the time goes.

## Use case

I was asked to test an OpenAI-shaped HTTP API (a small router in front of mock models) published through a quick tunnel, over two transports: the public HTTPS URL, and the raw byte stream of `--forward` through `cfrs connect`. The question was whether the tunnel carries streaming, large bodies, error statuses and concurrency faithfully, and what it costs. Fidelity on the raw path was fine (see the #198 comment). Cost is the open point.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` asset.
- Debian 13, kernel 6.12.113+deb13-amd64, x86_64, 8 CPUs. The only egress is an authenticated HTTP `CONNECT` proxy on 127.0.0.1:3128. No direct route, no system DNS for the tunnel name.
- Tunnel: a quick tunnel I did not create (the operator ran the server side), `quic` leg. Edge colo from the `cf-ray` suffix: `BOM`.
- Date 2026-11-03, 13:30 to 13:45 UTC.

## Reproduction

```
cfrs pod -- cfrs connect wss://<name>.trycloudflare.com/__cfrs/ws -L unix:///tmp/raw.sock
```

Client: Python `http.client` over `AF_UNIX` to `/tmp/raw.sock`, `Host: <name>`, `POST /v1/chat/completions` with a 1-message body to an instant mock model. 25 requests on one connection, then 8 requests each on a new connection. The HTTPS control is the same request over one kept-alive TLS connection that goes through the same proxy with `CONNECT`.

## Measured

Interleaved, run twice:

| Path | n | p50 | min | max |
| --- | --- | --- | --- | --- |
| raw, one connection | 25 | 1450 ms, 1453 ms | 1381, 1391 | 2205 (p95) |
| raw, new connection each | 8 | 1441 ms, 1426 ms | 1400, 1384 | 2268, 1483 |
| HTTPS, kept alive (control) | 25 | 356 ms, 368 ms | 343, 354 | 588 |

Other numbers on the raw path: 4 MiB body 619 KiB/s (6.74 s); 2 MiB prompt 3.4 s; first byte of a `slow-headers` answer 6485 ms against 5400 ms over HTTPS. Content was exact in every case.

Confounders: `cfrs pod` is in the path and I have no raw measurement without it, because `connect` does not work outside it on this host. Plain `curl` through the proxy is bimodal on its own (0.39 s or 1.6 s, 3 runs each, inside and outside the pod), so some of the spread is the proxy.

## What I would like

1. A way to see the time per stage for each forwarded connection, for example `connect -v` logging dial, TLS, WebSocket upgrade and first byte, each in ms. That would settle whether the 1.1 s is the proxy, the upgrade or the pod.
2. A statement in the docs of the expected extra latency of `--forward` against the HTTPS URL, with the conditions it was measured under. I was handed a figure of "about 70 ms more" and could not reproduce it, so I cannot say whether my host or the figure is the outlier.

## Dupe check

Searched `latency`, `connect`, `forward`, `pod`. #51 (closed) is forward throughput, #100 is MASQUE throughput, #198 and #191 are the proxy bypass. Nothing reports per-request latency of `connect`.
````

Comment of `Azathothas`, 2026-11-03T23:18:38Z:

````markdown
Done in 20d0c6c and 28dc607: -v logs the TCP, TLS and upgrade time of each WebSocket of connect, the local TCP sockets have TCP_NODELAY, and the live throughput step prints the median of 20 small requests over the URL and over connect. A fix of a gap waits for those numbers (in the Open work of docs/maintenance.md).

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="207"></a>

## #207: connect: probe the upstream at start, --detach/--name/ps like tunnel, and say what a netns pod hides

Opened 2026-11-03T13:45:10Z by `aerrand-agent`. State: closed, closed 2026-11-03T23:19:14Z. Labels: none.

````markdown
## Summary

Three requests from one test session of `cfrs connect` on a proxy-only host. None of them is a defect on its own. They are the things that cost me the most time while working around #198.

## Use case

I tested an HTTP API behind a quick tunnel over two transports (public HTTPS URL, and `--forward` through `cfrs connect`) and needed the second one to run unattended next to a test harness. Details of the host are below.

## Requests

### 1. `connect` should verify its upstream at start, and exit non-zero when it cannot

Today the listener binds, prints its banner and keeps running, and every local connection is accepted and then reset. The failure only appears as a `WARN` line in the log on the first client connection, and the process exit code stays 0 until `--run-for` ends. I only found out the transport was dead by running a client. Measured: after `cfrs connect ... -L tcp://127.0.0.1:9100` on this host, `exec 3<>/dev/tcp/127.0.0.1/9100` succeeds, the first read gives `Connection reset by peer`, and `pgrep` still shows the process.

Ask: dial the WebSocket once before accepting clients (or offer `--check`), and exit with the code the other commands use for an unreachable path (69, per #173) when the dial fails. This is the same idea as `tunnel --check` for the other end.

### 2. `connect --detach --name N` with a ready document, listed by `cfrs ps`

`tunnel` has `--detach`, `--name`, a ready document (#70) and `ps`. `connect` has none of them, so I started it with `setsid` and a log file and had to kill it by process name (a `pkill -f` pattern that contained the command line killed my own shell once). `connect` is the client half of the same pair and is the one a script has to supervise.

Ask: the same `--detach`, `--name`, ready document and `ps` row, with the listener paths in the document.

### 3. Say in `connect --help` and `pod --help` what a pod hides

Inside `cfrs pod` on the netns backend, `-L tcp://127.0.0.1:PORT` is bound in the pod's own network namespace and cannot be reached from the host (`curl: (7) Failed to connect to 127.0.0.1 port 9100`), while `-L unix:///path` can. `cfrs pod doctor` on this host reports `netns: available`, `seccomp: unavailable`. #80 documents that loopback goes direct under seccomp, but nothing says what happens under netns. It took two tries to find out.

Ask: one line in `pod --help` ("under netns, listeners the program binds are not visible outside the pod; use a unix socket"), and optionally a warning from `pod` when the program prints a loopback tcp listener.

## Environment

- cfrs `0.3.0-beta.8 (df99e331c5395ead24c5d1394ebeef0b8c94b65f)`, prebuilt `x86_64-unknown-linux-musl` asset.
- Debian 13, kernel 6.12.113+deb13-amd64, x86_64. Only egress is an authenticated HTTP `CONNECT` proxy on 127.0.0.1:3128. No system DNS for `*.trycloudflare.com`. `cfrs pod doctor`: `unshare(CLONE_NEWNET)` no, `unshare(NEWUSER|NEWNET)` ok, seccomp user-notif no.
- Date 2026-11-03.

## Dupe check

Searched `connect detach`, `connect ps`, `connect ready`, `connect probe`, `pod loopback netns`. Related and not the same: #198 and #191 (proxy bypass), #202 (socket file survives exit), #203 (the forward URL is missing from the ready document), #70 (`--detach` for `tunnel`), #80 (loopback under seccomp). Request 1 overlaps the last sentence of #198 ("exit 0, no other message") but asks for a startup probe, not a better message.
````

Comment of `Azathothas`, 2026-11-03T23:18:40Z:

````markdown
Fixed in c03b03a (request 1, the probe at start, exit 69, --no-check) and 20d0c6c (requests 2 and 3: --detach, --name, the ready document and ps; the netns note in the help of connect -L and pod --backend, and in the pod-netns README). Tests: `tests/connect.rs` `connect_exits_69_when_the_remote_does_not_answer`, `connect_detach_is_in_ps_and_stops`.

Released in v0.3.0-beta.10 (release run 41718791581; release-proofs 41720532960 checked the files, the signatures and a rebuild of x86_64 and aarch64).

---
_Generated by [Claude Code](https://claude.ai/code)_
````

<a id="259"></a>

## #259: egress: an unresolvable proxy host recurses through DoH and aborts with a stack overflow (exit 134)

Opened 2026-11-04T03:40:07Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

When the egress proxy host cannot be resolved by the system resolver, `cfrs` recurses through its own DoH fallback and aborts with a stack overflow. The process dies with SIGABRT (exit 134) instead of reporting a proxy error.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64, rustc 1.99.1, debug build. Any host whose `HTTPS_PROXY` or `--proxy` names a host that DNS does not answer hits this, including a typo and an internal proxy name that only the proxy's own resolver knows.

```console
$ env -i PATH=/usr/bin:/bin HOME=/tmp \
    HTTPS_PROXY='http://proxy.invalid:8080' CFRS_EDGE=127.0.0.1:9 \
    ./target/debug/cfrs tunnel --hello-world --service-url https://api.example
exit=134
thread 'main' (60584) has overflowed its stack
fatal runtime error: stack overflow, aborting

$ env -i PATH=/usr/bin:/bin HOME=/tmp \
    ./target/debug/cfrs --proxy http://proxy.invalid:8080 update --check
exit=134
thread 'main' (60618) has overflowed its stack
fatal runtime error: stack overflow, aborting
```

Control, a proxy host that resolves but refuses the connection:

```console
$ env -i PATH=/usr/bin:/bin HOME=/tmp HTTPS_PROXY='http://localhost:9' \
    ./target/debug/cfrs update --check
exit=69
... connecting to localhost:9: 2 addresses ([::1]:9, 127.0.0.1:9): Connection refused (os error 111)
```

Cause, read from the code: `Proxy::open` (`src/egress.rs:250-252`) resolves the proxy host with `resolve::resolve`, which falls back to DoH (`src/resolve.rs:205-237`). The DoH request is a `fetch` (`src/resolve.rs:382`), and `fetch::send` dials through `egress::dial` (`src/fetch.rs:175-183`), which opens the same proxy again. Each level adds a stack frame until the stack is exhausted. The control above shows the path when resolution succeeds.

## Dev work

Resolve the proxy's own host with the system resolver only, never through the DoH fallback, so `Proxy::open` cannot re-enter the proxy. A `.invalid` host must produce a normal "cannot resolve the proxy host" error with exit 69.

Add a regression test with `HTTPS_PROXY=http://proxy.invalid:8080` (the `.invalid` TLD is reserved and never resolves). The test must assert a clean error, not a child killed by SIGABRT.

Observed: both commands and the control were run, and the exit codes are from the shell. Inferred: the exact recursion path is from the cited lines.
````

<a id="260"></a>

## #260: instances: logs, stop and wait accept an unvalidated name and reach outside the run directory

Opened 2026-11-04T03:40:08Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

`cfrs logs`, `cfrs stop` and `cfrs wait` pass the instance name straight to `instances::paths` (`src/instances.rs:97`), which formats `{name}.json`, `{name}.lock`, `{name}.child.lock` and `{name}.log` into a path. They never call `instances::check_name` (`src/instances.rs:79`), although `detach::register` (`src/detach.rs:223`), `detach::start_inner` (`:465`) and `autostart` (`src/autostart.rs:332`) do. A name with `..` or an absolute path therefore leaves the run directory.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64, `CFRS_RUN_DIR` set to a temporary directory.

Read a file outside the run directory, exit 0:

```console
$ echo 'SECRET-CONTENT-1234' > $BASE/dir/secret.log
$ CFRS_RUN_DIR=$BASE/run cfrs logs ../dir/secret
SECRET-CONTENT-1234
exit=0
```

Delete the record and locks of an instance outside the run directory:

```console
$ printf '{"name":"victim"}\n' > $BASE/dir/victim.json
$ touch $BASE/dir/victim.lock $BASE/dir/victim.child.lock
$ CFRS_RUN_DIR=$BASE/run cfrs stop ../dir/victim --timeout 1
cfrs: no instance /tmp/.../dir/victim runs (cfrs ps)
exit=69
$ ls -A $BASE/dir
(no victim.json, no victim.lock, no victim.child.lock)
```

Create lock files outside the run directory:

```console
$ CFRS_RUN_DIR=$BASE/run cfrs wait $BASE/dir/secret --timeout 1
cfrs: no instance /tmp/.../dir/secret (cfrs ps)
exit=69
$ ls -A $BASE/dir
secret.child.lock  secret.lock  secret.log
```

Observed: all three commands and their outputs. Inferred: a wrapper that derives the name from an untrusted value turns this into an arbitrary-file read and arbitrary-file delete. A signal to a pid in a crafted record was attempted and refused in this run (exit 69, the target process stayed alive), so the kill path is not claimed here.

## Dev work

Call `instances::check_name` at the start of `instances_stop` (`src/main.rs:1403`), `instances_logs` (`src/main.rs:1429`) and the `Wait` arm (`src/main.rs:1970`), or make `instances::paths` return `Result` and validate there so no future caller can forget. A bad name should exit 64 with the same message that `--detach --name` uses.

Add one test per command: a name with `..` and an absolute path must fail with 64 and touch nothing.
````

<a id="261"></a>

## #261: net switch: a --listen unix:PATH that is a regular file is deleted, and a live socket is taken over silently

Opened 2026-11-04T03:40:09Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

`cfrs net switch --listen unix:PATH` calls `std::fs::remove_file(path)` unconditionally before binding (`src/vnet/switch.rs:195`). A regular file at PATH is destroyed, and a socket that another live instance owns is silently replaced.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64.

Data loss, observed:

```console
$ printf 'IMPORTANT-DATA\n' > $BASE/notes.txt
$ cfrs net switch --listen unix:$BASE/notes.txt --detach --name del
cfrs: switch   unix:/tmp/.../notes.txt
{"command":"net switch","event":"detached",...,"name":"del","pid":60656}
exit=0
$ stat -c %F $BASE/notes.txt
socket
$ cat $BASE/notes.txt
cat: /tmp/.../notes.txt: No such device or address
```

Live socket takeover, observed earlier in the same pass: a first instance holds `unix:$BASE/s.sock`, a second instance starts with the same path and exits 0. `cfrs ps` then lists both as ready, and both report the same listen address, but the path belongs to the second.

Compare `feature::MetricsEndpoint::bind` (`src/feature/mod.rs:723-733`), which stats the path and refuses to remove a non-socket. Issue 202 fixed the same class for `connect -L` only; the `net switch` path still unlinks anything.

## Dev work

Before the bind, `stat` the path. Refuse when it exists and is not a socket, and refuse a socket that a live server accepts unless a new explicit `--replace` is given. Keep the current remove for a stale socket that no process accepts.

The error must name the path and exit 64 or 78, not 1. A test with a regular file and a test with a live socket pin both cases.
````

<a id="262"></a>

## #262: detach: a foreground --name record keeps the raw argv, so --proxy credentials appear in cfrs ps --json

Opened 2026-11-04T03:40:10Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

A foreground instance that has a `--name` writes its raw argv to the instance record (`src/detach.rs:234-235`): `args: std::env::args().skip(1).collect()`. The `--detach` path runs the argv through `autostart::split_secrets` (`src/detach.rs:455-465`), so it keeps the proxy password out of the record. The foreground path does not. `cfrs ps --json` then prints the record, including the credential.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64, temporary `CFRS_RUN_DIR`.

```console
$ cfrs --proxy 'http://user:hunter2@127.0.0.1:9' \
    net switch --listen unix:$BASE/fg.sock --name leakfg &
$ cfrs ps --json
{"instances":[{"args":["--proxy","http://user:hunter2@127.0.0.1:9","net","switch",
  "--listen","unix:/tmp/.../fg.sock","--name","leakfg"], ...}]}

$ jq -r .args $BASE/run/leakfg.json
["--proxy","http://user:hunter2@127.0.0.1:9",...]
```

Observed: both outputs. The record is 0600, but any process that can run `cfrs ps` as the same user, and any bug report or log capture that includes the JSON, sees the password. The same applies to `--token` and any other value that `split_secrets` moves.

## Dev work

Run the foreground record's argv through `autostart::split_secrets` too, keep the moved values in the process environment, and write them to the private `NAME.env` file that issue 71 specifies. The record and `ps --json` must show the placeholder, not the value.

Add a test that starts a foreground instance with `--proxy http://u:p@...`, reads the record, and asserts the password does not appear.
````

<a id="263"></a>

## #263: detach: --detach writes a human line before the JSON document, so the output is not one JSON document

Opened 2026-11-04T03:41:38Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

`--detach` documents one JSON document on stdout. The parent copies every non-`READY` line of the child to its own stdout (`src/detach.rs:571`), so a child that prints a human line before it is ready puts that line in front of the JSON.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64, temporary `CFRS_RUN_DIR`.

```console
$ cfrs net switch --listen unix:$BASE/j.sock --detach --name j1 2>/dev/null
cfrs: switch   unix:/tmp/.../j.sock
{"command":"net switch","event":"detached","listen":"unix:/tmp/.../j.sock","log":"...","name":"j1","pid":60704}

$ cfrs net switch --listen unix:$BASE/j2.sock --detach --name j2 2>/dev/null | jq -e .
jq: parse error: Invalid numeric literal at line 1, column 5
```

Observed: both outputs and the `jq` exit 5. The human line is not in the instance log (the log has the tracing line instead), so moving it to stderr loses nothing.

## Dev work

In `wait_ready_child`, write every non-`READY` line to stderr, not stdout. Add a test that pipes the `--detach` output through `serde_json::from_str` and requires exactly one document.
````

<a id="264"></a>

## #264: instances: stop on an unreadable record deletes the live instance locks, orphaning the child and freeing the name

Opened 2026-11-04T03:41:39Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

When the record of a running instance is missing or unreadable, `cfrs stop NAME` calls `instances::remove` (`src/main.rs:1412-1416`, `src/instances.rs:229-235`). That unlinks `NAME.json`, `NAME.lock` and `NAME.child.lock` while the live child still holds the locks open. The child keeps running, `cfrs ps` no longer lists it, and a new instance can take the name and the listen path.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64, temporary `CFRS_RUN_DIR`.

```console
$ cfrs net switch --listen unix:$BASE/c.sock --detach --name cor
$ CPID=$(jq -r .pid $BASE/run/cor.json)
$ : > $BASE/run/cor.json
$ cfrs stop cor --timeout 2
cfrs: no instance cor runs (cfrs ps)
exit=69
$ ls -A $BASE/run
cor.log  cor.start
$ kill -0 $CPID && echo alive
alive
```

Observed: the record and both lock files were removed, `stop` exited 69, and the child stayed alive. A second start with the same name then succeeds and takes the same socket path.

The trigger is a lost or truncated record. `instances::write` renames atomically but does not fsync, and a runtime-directory cleaner can remove the files. Issue 71's premise is "alive means the lock is held"; this error path throws that evidence away.

## Dev work

Never unlink a lock file in the error path. When the record is unreadable but a lock is held, report the instance as live or unknown, and keep the locks so a second start cannot take the name. A test with a truncated record and a held lock pins it.
````

<a id="265"></a>

## #265: autostart: --from drops the secrets that --detach moved out of argv, and explicit args keep --detach

Opened 2026-11-04T03:41:40Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

Three autostart defects, one of them loses a credential at boot.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64, temporary `HOME`, `XDG_STATE_HOME` and `CFRS_RUN_DIR`.

### 1. `autostart add --from NAME` drops the secrets that `--detach` moved out of argv (major)

`src/main.rs:2265-2273` copies `record.args` only. `--detach` removes `--proxy` and `--token` from the argv (`src/detach.rs:455-465`) and never writes `NAME.env`, so there is nothing to copy.

```console
$ cfrs --proxy 'http://u:pw@127.0.0.1:9' net switch --listen unix:$BASE/x.sock --detach --name fromme
$ jq -r .args $BASE/run/fromme.json
["net","switch","--listen","unix:/tmp/.../x.sock","--detach","--name","fromme"]
$ cfrs autostart add fromone --from fromme
$ cat $BASE/state/cfrs/autostart/fromone.args
["net","switch","--listen","unix:/tmp/.../x.sock"]
$ grep -c CFRS_PROXY $BASE/state/cfrs/autostart/fromone.env
0
```

Observed. The unit starts the command without its proxy, so the entry fails at the next boot. Issue 71 and issue 23 both promise a private env file.

### 2. Explicit args keep `--detach` and `--name` (minor)

`autostart_args` (`src/main.rs:2237`) only rejects a leading `cfrs` and the meta commands. `--from` strips the detach options (`without_detach_options`, `src/main.rs:2272`); explicit args do not.

```console
$ cfrs autostart add bad -- net switch --listen unix:$BASE/b.sock --detach --name inner
$ cat $BASE/state/cfrs/autostart/bad.args
["net","switch","--listen","unix:/tmp/.../b.sock","--detach","--name","inner"]
$ cfrs autostart run bad --dir $BASE/state/cfrs/autostart; echo $?
0
```

Observed: the unit's main process exits 0 at once, the supervisor sees success, and the real server is a detached child.

### 3. `run_limited` polls `try_wait` without draining the pipes (minor)

`src/autostart.rs:80-122` calls `child.try_wait()` in a loop and only calls `wait_with_output()` after the child exits. A helper that writes more than a pipe buffer blocks in `write` and never exits.

```console
$ (fake crontab -l that prints 4000 lines)
$ cfrs autostart add big -- net switch --listen unix:$BASE/b.sock
cfrs: no way to start at boot: ...; crontab -l did not end in 10 s. ...
exit=69
```

Observed: a healthy `crontab` was killed and the command reported that no boot method exists.

### 4. The systemd unit uses sh quoting and leaves `%` unescaped (nit)

`src/autostart.rs:250-270` writes a `'\\''` sh-quoted `ExecStart=` line. systemd expands `%` specifiers in `ExecStart` even inside single quotes, so a state directory containing `%h`, `%u` or `%t` points the entry at another path. `systemd-analyze verify` shows the expansion with `/tmp/%h/cfrs`.

## Dev work

- Write the split secrets to `NAME.env` (0600) when an instance starts, and have `--from` copy that file. Or refuse `--from` when the record's argv was reduced.
- Apply `without_detach_options` to explicit args too, or reject `--detach` and `--name` with a usage error.
- Read stdout and stderr concurrently in `run_limited`, with the watchdog around the whole exchange.
- Escape `%` as `%%` in the unit, and use systemd quoting rather than sh quoting.

Observed: items 1, 2 and 3. Read: item 4, with the `systemd-analyze verify` line from the generated text.
````

<a id="266"></a>

## #266: status and instance probes write to disk although the commands are documented as read-only

Opened 2026-11-04T03:41:42Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

Two commands that the documentation describes as read-only change the filesystem.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64, fresh `HOME` and `XDG_*` directories.

### 1. `status` and `bug-report` create directories

`src/status.rs:1-6` says `cfrs status` "writes nothing". `src/status.rs:104` calls `instances::run_dir()`, which creates `cfrs/run`, and `instances::list` (`src/instances.rs:245-273`) removes records whose lock is free. `bug_report::text` uses the same two calls.

```console
$ cfrs status
$ find $BASE -mindepth 1
$BASE/run
$BASE/state/cfrs
```

Observed: both directories appear after a status on a fresh tree. Read: `instances::list` also prunes stale records, so a status can delete the evidence of an ended instance.

### 2. Probing a name that does not exist creates lock files

`instances::is_alive` opens both lock files with `.create(true)` (`src/instances.rs:176-187`, `:221-227`).

```console
$ cfrs wait nosuch --timeout 1
cfrs: no instance nosuch (cfrs ps)
exit=69
$ ls -A $CFRS_RUN_DIR
nosuch.child.lock  nosuch.lock
```

Observed.

## Dev work

Use an existing-directory helper and a non-mutating list for `status` and `bug-report`. Open the locks without `create` for an aliveness probe; a missing lock means not alive. Add a test that runs `status` in a fresh tree and asserts the tree is unchanged.
````

<a id="267"></a>

## #267: bug-report: redaction misses Authorization values and bare hex tokens

Opened 2026-11-04T03:41:44Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

`cfrs bug-report` says "Ids, tokens and credentials are hidden". `report::mask` (`src/report.rs:148`) hides URL userinfo, proxy values and values passed to `hide()`, but not an `Authorization` header value and not a bare hex token.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64. The lines were appended to a live instance log, then `cfrs bug-report` was run.

```console
$ cfrs bug-report | grep -E 'Authorization|0123456789abcdef'
auth Authorization: Basic dXNlcjpwYXNzd29yZA==
account 0123456789abcdef0123456789abcdef and api 0123456789abcdef0123456789abcdef01234567
```

The same run did mask `http://user:pass@proxy` as `http://<hidden>@proxy`. Observed. No current log line emits a Basic header or a bare hex token, so this is latent rather than a live leak, but a bug report is the one artifact a user pastes in public.

## Dev work

Mask the value after `Authorization:` (Basic and Bearer), and runs of 32 or 40 hex characters, in `report::mask`. Add a unit test next to `mask_hides_url_credentials_and_hidden_values`.
````

<a id="268"></a>

## #268: metrics: the cloudflared-compatible endpoint is unreachable and no command exposes it

Opened 2026-11-04T03:41:45Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

`src/util/metrics.rs` and `feature::MetricsEndpoint` implement a cloudflared-compatible `cloudflared_*` endpoint on a unix socket. The doc comments say an existing cloudflared scrape configuration keeps working. No command binds it.

```console
$ grep -rn 'MetricsEndpoint::bind' src/
src/feature/mod.rs:1734: ... (tests only)
$ cfrs --help | grep -i metrics
(no output)
```

Observed. `MetricsEndpoint::bind` is called only from tests (`src/feature/mod.rs:1734,1770,1787,1794`), and `grep -n metrics src/main.rs` finds no option or subcommand. The reachable metrics are the `cfrs_*` families through `Service::Metrics` over the tunnel, and README line 362 says the cloudflared `metrics` config key is ignored.

## Dev work

Either wire the endpoint behind a `--metrics-listen` option or a config key, with the same auth and path rules as the rest of the listeners, or delete `src/util/metrics.rs` and `MetricsEndpoint` with their claims. Shipping an unreachable compatibility surface in a stable release is a promise the binary does not keep.
````

<a id="269"></a>

## #269: config: three cloudflared semantics are missing (token/url/hello-world, the empty-ingress check, and path as a regex)

Opened 2026-11-04T03:42:48Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

Three cloudflared config semantics are missing or wrong. Each changes what a copied config does.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64. All commands below were run.

### 1. `token:` is accepted and ignored, so a named-tunnel config becomes a quick tunnel (major)

`CLOUDFLARED_KEYS` (`src/config.rs:340-370`) includes `token`, `url` and `hello-world`, but `RawConfig` (`src/config.rs:324-335`) has no fields for them. A key outside the list is an error, so these three look supported and are then dropped. With no `tunnel:` and no `credentials-file:`, the loader picks a quick tunnel.

```console
$ cat token.yml
token: eyJhIjoiYSIsInQiOiJmZmQ4NmJkNS0xYmZmLTQ1NmItOGMyYy03NWEwMTRjZGM0YzgiLCJzIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOD0ifQ==
ingress:
  - service: http_status:404
$ cfrs tunnel --config token.yml --check --json
INFO cfrs::config: token.yml has no tunnel: and no credentials-file:; cfrs starts a quick tunnel
... "tunnel":{"kind":"quick","service":"https://api.trycloudflare.com"} ... "ok":true
```

Observed. The token in the example is synthetic. A user who copies a cloudflared token config gets an unauthenticated public quick tunnel instead of the named tunnel they configured. That is the wrong side of the safety decision.

### 2. `url:` and `hello-world:` are accepted and ignored, and `--check` passes an empty ingress (major)

```console
$ printf 'url: http://127.0.0.1:9\n' > url.yml
$ cfrs tunnel --config url.yml --check --json
... "ingress":[] ... "ok":true
$ cfrs tunnel --config url.yml
cfrs: no ingress rules configured
exit=1

$ printf 'ingress: []\n' > empty.yml
$ cfrs tunnel --config empty.yml --check --json
... "ingress":[] ... "ok":true
$ cfrs tunnel --config empty.yml
cfrs: no ingress rules configured
exit=1
```

Observed. cloudflared turns `url:` into a catch-all rule and `hello-world: true` into the hello-world service. `--check` (`src/preflight.rs:129-134`) iterates the rules and never requires one, so it reports success for a config that cannot start.

### 3. `path:` is a literal prefix, not a regex (major)

`src/ingress.rs:194-198` uses `path.starts_with(prefix)`. cloudflared compiles `path` as a regular expression, and the repository's own YAML test uses one (`src/yaml.rs:400`: `path: ^/api/.*$`). A rule copied from a cloudflared config therefore matches only the literal string `^/api/.*$`, never `/api/x`, and the request falls through to the next rule. The failure is silent.

## Dev work

- Parse `token:` into `Credentials::Token` and validate it, or refuse it with a message that names the key. Do not fall through to a quick tunnel.
- Convert `url:` to a catch-all `Service::Http` rule and `hello-world: true` to `Service::HelloWorld` when `ingress:` is absent, or refuse both with a message.
- Make `--check` and the loader fail when the ingress list is empty, with the same message the run uses.
- Compile `path` as a regex at load, reject an invalid one with the file and rule, or reject a regex-looking path with an explicit error and document prefix matching.

Add one test per item: a token-only config, a url-only config, an empty ingress under `--check`, and a regex path.
````

<a id="270"></a>

## #270: install.sh: DEBUG prints GITHUB_TOKEN, busybox wget is chosen before python3, and seven install-path defects

Opened 2026-11-04T03:42:50Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

Nine defects in `scripts/install.sh`. The first two were run in this pass; the rest are read from the script with the line that causes each.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64. All fake downloaders were local; no real install and no request to the release host.

### 1. `DEBUG=1` prints `GITHUB_TOKEN` (major, observed)

`set -x` is enabled at the top of `main` (`scripts/install.sh:57`), and `fetch_api` passes the token in the curl argv (`:230-239`). The failure tail prints the trace (`:297`).

```console
$ env ... GITHUB_TOKEN=ghp_SUPERSECRETTOKEN DEBUG=1 sh scripts/install.sh
+ curl -fsSL --proto =https --tlsv1.2 -H Authorization: Bearer ghp_SUPERSECRETTOKEN -o ... https://api.github.com/...
```

Observed. The token is also an argv of the running curl, so it is visible in `ps` while the request runs.

### 2. A busybox `wget` is chosen before `python3` (major, observed)

`detect_downloader` (`scripts/install.sh:169-190`) accepts the busybox applet at the `wget` slot and returns `wget-busybox`. The list order is `curl wget aria2c http python3 python perl busybox`, so a host with a busybox `wget` and a working `python3` still gets the insecure downloader. The comment on the function says "busybox wget goes last".

```console
$ env ... CFRS_DOWNLOADER="wget python3" sh scripts/install.sh
cfrs install: downloader: wget-busybox; target: x86_64-unknown-linux-musl
cfrs install: busybox wget does not check TLS certificates: a host on the path can change the files.
```

Observed. Issue 174 is closed; this is the remaining selection path.

### 3. A restrictive umask leaves the installed binary 0700 (minor, read)

`chmod 0755 "$tmp/$file"` (`:101`) then `cp` (`:102`). `cp` creates the destination with the source mode masked by the umask, so `umask 077` gives 0700. `src/update.rs:655-661` uses `OpenOptions::mode(0o755)`, which the umask also masks.

### 4. The cleanup list is split on spaces (minor, read)

`new_files="$new_files $new"` (`:100`) and `rm -f $new_files` (`:122`). An install directory with a space leaves `.cfrs.new.$$` behind after a failed run.

### 5. `mv` into an existing directory reports success (minor, read)

`mv -f "$dir/.$name.new.$$" "$dir/$name"` (`:108`). If `$dir/$name` is a directory, `mv` moves the file inside it, exits 0, and the script prints `installed`.

### 6. The new file has a predictable name and `cp` follows a symlink (minor, read)

`new="$dir/.$name.new.$$"` (`:100`) and `cp` (`:102`). A process that can write the install directory and learns the pid can pre-create that path as a symlink; `cp` follows it and overwrites the target.

### 7. The installed binary is not checked against the requested tag (minor, read)

`run_version` checks only the exit status (`:103-105`, `:125-131`). A release whose binary prints `cfrs 9.9.8` is installed as `v9.9.9`. `cfrs update` does compare (`want = "cfrs {tag} "`).

### 8. `latest` selects a draft release (minor, read)

`resolve_tag` (`:281-305`) extracts every `"tag_name"` from the API JSON, including entries with `"draft": true`, and `highest` (`:308-335`) picks the highest. A draft above the newest public tag is chosen.

### 9. An empty file is reported as a downloader exit 1 (minor, read)

`fetch` returns the status of `[ -s "$out" ]` (`:208-216`), and `get` prints that as the downloader's exit (`:218-227`). A curl that exits 0 with 0 bytes is reported as "exit 1 of curl".

## Dev work

- Keep `set -x` off around `fetch_api`, and pass the token through a private header file (`curl -H @FILE`), so it is neither in the trace nor in argv.
- When `wget --help` says BusyBox, `continue` the search (or move `wget-busybox` after the other tools).
- `chmod 0755` the installed file after the copy and the rename.
- Keep temp paths in a newline-separated list and remove each with a quoted loop.
- Refuse when `$dir/$name` exists and is not a regular file.
- Create the new file with `mktemp` in the install directory, then copy into the created file.
- Require the first `--version` line to start with `cfrs ${tag#v} ` before the `mv`.
- Filter `"draft": true` before choosing the highest tag, as `cfrs update` does.
- Report an empty download as empty, not as the downloader's exit.
````

<a id="271"></a>

## #271: share: the PIN redirect loses &, If-None-Match ignores *, the idle clock starts before provisioning, and responses have no Cache-Control

Opened 2026-11-04T03:42:51Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

Four small share-path defects. Each was read in the code; the first was also exercised through `Gate::page` in the review.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64.

### 1. The PIN page drops `&` from `next` (minor)

`escape_attr` (`src/gate.rs:187-193`) filters `&` instead of escaping it, and the hidden field is `value="{next}"` (`:180`). A gated URL `/s/<token>/?x=1&y=2` becomes `next="/s/<token>/?x=1y=2"`. After a correct PIN the browser posts the mangled value and `unlock_response` redirects to it. In proxy mode the origin receives merged parameters.

### 2. `If-None-Match: *` is not a match (minor)

`src/share.rs:864-871` compares each token byte-exact with the ETag. RFC 9110 section 13.1.2: `*` matches any current representation, so a GET should answer 304. A weak validator `W/"a-6aea9221"` is also not matched, although weak comparison should accept it.

### 3. The idle clock starts before the tunnel is provisioned (minor)

`ShareControl::default` sets `last = Instant::now()` (`src/share.rs:169-177`). `ServiceRuntime::build` runs before quick-tunnel provisioning (`src/tunnel.rs:170`), and `wait_with_idle` starts only after the ready line (`src/main.rs:2905`, `:3279-3300`). With `--idle-secs N`, a provisioning that takes N seconds ends the session at the first tick after ready. `--run-for` is measured after ready (`src/main.rs:2850`), so the two budgets start at different points.

### 4. Session responses carry no `Cache-Control` (nit)

The download response (`src/share.rs:915-930`) and the landing pages set no `Cache-Control`. `--stop-after` promises one delivery; a caching intermediary is not told to keep the body out of its cache. Compare `feature::StaticServer`, which sets the header (`src/feature/mod.rs:1175-1180`).

## Dev work

- HTML-escape `&` as `&amp;` (and the quotes as entities) in `escape_attr` instead of deleting it.
- Treat `*` as a match and compare validators with the weak prefix stripped.
- `touch()` each share control when the tunnel is ready, before the ready line.
- Send `Cache-Control: no-store` on the session responses.

Observed: the `escape_attr` behavior through the gate page. Read: items 2 to 4. A live edge test with a `.zip` and `--stop-after` would settle whether an intermediary caches the download.
````

<a id="272"></a>

## #272: edge_h2: no handshake deadline, a failed attempt keeps serving, and a config push is unbounded

Opened 2026-11-04T03:42:52Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

Four edge HTTP/2 defects. Each is read in the code; the first two were also exercised with a stalled peer and a dropped handle in the review.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64. The real edge is not reachable here, so the peer-side consequence is inferred.

### 1. No deadline on the HTTP/2 handshake (minor)

`serve_connection` calls `h2::server::Builder::handshake(io).await` with no timeout (`src/edge_h2.rs:376-380`). `DIAL_TIMEOUT` covers TCP and TLS only (`:41-42`), and `REGISTER_TIMEOUT` starts after the handshake (`:552`). An edge or load balancer that accepts TLS and then sends nothing hangs `connect_one` with no log and no reconnect. The QUIC path has `HANDSHAKE_TIMEOUT = 10 s` (`src/cloudflare/quic.rs:34`).

### 2. A failed or cancelled attempt leaves the connection serving (minor)

`connect_one` holds the `serve` handle (`src/edge_h2.rs:544-550`) and returns on the error paths at `:552-566` without aborting it. A dropped `JoinHandle` detaches the task, and the h2 connection keeps accepting streams. In the review, a test that dropped the control, draining and serve handles still got a 200 from the connection. Each failed attempt during an outage leaves a task and a TLS socket until the edge closes it.

### 3. A configuration push is read with an unbounded `read_to_end` (minor)

`answer_configuration` (`src/edge_h2.rs:668`) calls `reader.read_to_end(&mut text).await?` with no size cap and no deadline. One authenticated edge push can grow memory without limit, and a push that never ends pins the stream task.

### 4. The H2 server advertises `u32::MAX` concurrent streams (nit)

`src/edge_h2.rs:376` sets `max_concurrent_streams(u32::MAX)`; QUIC uses `MAX_EDGE_STREAMS = 256` (`src/cloudflare/quic.rs:43-46`). Each stream costs a task and two 64 KiB duplex buffers plus a 16 KiB pump buffer, so a non-compliant edge can ask for more memory than the host has.

### 5. The request-head builder and the RPC dispatcher are not fuzzed (nit)

`src/fuzzing.rs:68-78` drives only the decode helpers of `rpc_message`, and `connect_request` decodes only. No target feeds `build_request_head`, `FrameScan::feed` or `rpc::Session::handle`. Issue 226 (CR/LF in `build_request_head`) is the kind of defect such a target would find.

## Dev work

- Wrap the handshake in a `DIAL_TIMEOUT`-class timeout.
- Abort the `serve` task on every error path and on cancellation, for example with a guard whose `Drop` calls `abort()`.
- Cap the configuration body at a few KiB and add a timeout, answering with the last applied version.
- Use `MAX_EDGE_STREAMS` for the H2 server too.
- Add a `build_request_head` target that asserts one request and no bare CR/LF in a field, and drive `Session::handle` with arbitrary frames.
````

<a id="273"></a>

## #273: ws/transport: 101 before the origin dial, an 8 s serial bound below the handshake budget, an IPv6 relay URL split wrong, and Direct always AF_INET

Opened 2026-11-04T03:43:55Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

Four data-path defects outside the edge client. Each is read in the code; the first three were also exercised in the review.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64. The real edge is not reachable here.

### 1. `ws`: the 101 is written before the origin is dialled (minor)

`src/ws.rs:88` writes the 101 and the upgrade headers, then `src/ws.rs:94` dials the forward target. A dead origin therefore reports an accepted WebSocket to the edge and then closes abnormally. In the review, a forward target whose dial failed still produced the 101 metadata (`HttpStatus: 101`, `Sec-WebSocket-Accept: ...`).

Dial first, then write the 101. Answer 502 on a dial failure.

### 2. `tunnel`: the serial failover bound is shorter than the leg's own handshake (minor)

`DIRECT_ATTEMPT_TIMEOUT = 8 s` (`src/tunnel.rs:29`) wraps a serial attempt (`:227-240`, `:734-747`). The QUIC handshake alone allows 10 s (`src/cloudflare/quic.rs:34`), the H2 registration allows 30 s (`src/edge_h2.rs:41-46`), and `register_retrying` allows 3 tries (`src/tunnel.rs:692,716`). A slow but healthy edge is discarded in serial mode before any of those budgets can finish. In the review, a registration loop was cut at 8 s after two calls.

Derive the serial bound from the step budgets (at least `5 * HANDSHAKE_TIMEOUT + REGISTER_TIMEOUT`).

### 3. `ws_relay`: a bracketed IPv6 relay URL with a port is split wrong (minor)

`src/ws_relay.rs:115-124` uses `rsplit_once(':')` and rejects a host that contains `:`. For `https://[::1]:8443`, the host becomes `[::1]:8443` and the port stays 443, so the dial goes to `[::1]:8443:443`. The plain-http loopback check also rejects the bracketed form.

Strip a bracketed host before splitting the port, then compare the bare host with the loopback list.

### 4. `transport::Direct` always opens an IPv4 socket (minor, public API)

`src/transport/mod.rs:130-143` calls `TcpSocket::new_v4()` in both branches, for every resolved address. A `::1` listener is reachable, but `Direct::connect("::1", port, ...)` fails with `EAFNOSUPPORT (os error 97)`. The comment at `:111-112` promises an AAAA fallback. The module is public and has no in-tree caller.

Choose `new_v6()` or `new_v4()` from `addr.is_ipv6()`, and match the configured bind address family.
````

<a id="274"></a>

## #274: egress: socks5:// ignores --resolve, an unbracketed IPv6 proxy is parsed as :1, Digest is case-sensitive, and --proxy is over-redacted

Opened 2026-11-04T03:43:56Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

Four egress defects. The IPv6 parse and the over-redaction were run in this pass; the other two are read in the code and were exercised with a local proxy in the review.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64.

### 1. `socks5://` ignores `--resolve` and the DoH fallback (minor)

`socks5_connect` resolves the target with `tokio::net::lookup_host` (`src/egress.rs:477`), not `crate::resolve::resolve` (`src/resolve.rs:201-237`). A `--resolve HOST=IP` pin is not applied, and the DoH fallback is skipped, so a host with no system DNS cannot use a `socks5://` proxy. `socks5h://` works because the proxy resolves. The doctor reports "failed to lookup address information: Temporary failure in name resolution" and the proxy log has no entry.

Use `crate::resolve::resolve` for the SOCKS5 target, as the direct dial does.

### 2. An unbracketed IPv6 proxy URL is parsed as host `:` and port 1 (minor)

`split_host_port` (`src/egress.rs:1186-1225`) accepts `http://::1`: `rsplit_once(':')` gives `(":", "1")`, and the character check does not reject `:`.

```console
$ cfrs --proxy http://::1 --resolve ':=127.0.0.1' update --version v9.9.9 --check
cfrs: ... through the proxy http://[:]:1: connecting to the proxy http://[:]:1: connecting to ::1: 127.0.0.1:1: Connection refused
exit=69
```

Observed. Reject an unbracketed host that contains `:`, or accept it only as a valid IPv6 address with no port, and tell the user to write `[::1]`. This is also one trigger of issue 259.

### 3. Digest is recognised only with exact case and only as the sole scheme (minor)

`parse_challenge` (`src/proxy_auth.rs:77-79`) uses `strip_prefix("Digest")`, and `explain_407` (`src/egress.rs:626-668`) treats one header as one challenge. A proxy that sends `digest ...` or `Basic ..., Digest ...` gets a Basic answer only, even when the Digest challenge has `algorithm=MD5` and `qop=auth`, which cfrs supports. The review observed this with a local 407 proxy.

Match the scheme case-insensitively and extract the Digest challenge from a header that carries several schemes.

### 4. A credential-free `--proxy` is redacted to `<hidden>` (nit)

`src/main.rs:1838` passes the whole spec to `report::hide`.

```console
$ cfrs --proxy http://127.0.0.1:9 update --version v9.9.9 --check
cfrs: ... through the proxy <hidden>: connecting to the proxy <hidden>: connecting to 127.0.0.1:9: ...
```

Observed. The URL has no userinfo, so there is nothing to hide and the operator loses the address they need to fix. Hide only the userinfo part.
````

<a id="275"></a>

## #275: update: --force without --version reports up to date instead of reinstalling

Opened 2026-11-04T03:43:57Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

`cfrs update --force` without `--version` does not reinstall the current version. The help text says `--force` installs the release also when it is the version of this binary.

`plan` (`src/update.rs:456-466`):

```rust
if tag == current && !force {
    return if pinned { Plan::Same } else { Plan::UpToDate };
}
if !pinned && version_order(tag, current) != std::cmp::Ordering::Greater {
    return Plan::UpToDate;
}
```

With no `--version`, `pinned` is false and the newest tag equals the current tag. The first branch is skipped because `force` is true, and the second returns `UpToDate` because the order is `Equal`.

Issue 197 fixed the pinned `--version <same>` case and its test covers only `plan("v1","v1",true,false,true)`. The unpinned `--force` path is not covered.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), read from the code.

## Dev work

Return `Install` when `force` is set and `tag == current`, even when `pinned` is false, or exempt `tag == current && force` from the no-downgrade branch. Add `plan("v1","v1",false,false,true) == Plan::Install` to the test.
````

<a id="276"></a>

## #276: library: StaticDir reads whole files, blocks on a FIFO, and serves dotfiles, unlike the CLI static path

Opened 2026-11-04T03:43:58Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

The public `StaticDir` and `StaticServer` (`src/origin/static_files.rs`, re-exported through `src/feature/mod.rs:1108`) behave worse than the CLI's `serve --static` path. A crate consumer gets these defects through the published library.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64. Read from the code; the review exercised `StaticDir::respond` through a harness.

### 1. `send_file` reads the whole file into memory (major)

`src/origin/static_files.rs:156` calls `std::fs::read(path)`. A 1 GiB file costs 1 GiB of heap. The CLI path uses `tower_http::services::ServeDir` (`src/service.rs:108-130`) and streams.

### 2. A FIFO blocks the request forever (major)

`resolve` accepts any non-directory (`src/origin/static_files.rs:118`), and `send_file` then calls `std::fs::read` on it. A FIFO in the served root blocks the request task until the process is killed. The review's harness hung until an outer `timeout 5` killed it.

Open the path, require a regular file, and stream the body with a bounded copy.

### 3. Dotfiles are served (minor)

`resolve` (`src/origin/static_files.rs:60-70`) has no dot-segment check, so `.env` and `.git/config` are returned with 200. The CLI path rejects every segment that starts with `.` (`src/service.rs:187`), and its test asserts that (`:271-296`). A consumer who wraps a directory in `StaticServer` to put it behind a tunnel exposes the same files the CLI refuses to expose.

Reject dot segments in `StaticDir::resolve`, in one place, or document the difference.

## Dev work

Serve only regular files, stream the body, and reject dot segments. Add tests for a FIFO, a large sparse file, and `.env`. The existing public API can keep its shape.
````

<a id="277"></a>

## #277: preflight: --check reports the edge row PASS without making the lookup it names

Opened 2026-11-04T03:44:00Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

`cfrs tunnel --check` prints a passing `edge` row that says "edge discovery by DNS", but the check makes no lookup. The row comes from the configured override only, and `src/preflight.rs:4-5` says the check makes no call and opens no connection.

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64.

```console
$ cfrs tunnel --hello-world --check
  pass  tunnel        a quick tunnel; https://api.trycloudflare.com is not called in a check
  pass  edge          edge discovery by DNS
  pass  legs          planned: http2, then quic+warp (staggered by 2s); no edge connection is made (cfrs doctor tests the reach); ...
  pass  tls-roots     /etc/ssl/certs/ca-certificates.crt (148 roots), webpki-roots 1.0.11 (118 roots)
  pass  origin 1      hello_world: built in
cfrs: the check passed; nothing was started
exit=0
```

Observed. The `legs` row is honest about making no connection; the `edge` row is not. A host whose resolver cannot find the SRV record still gets a passing check and then fails at start.

## Dev work

Run a bounded `edge_discovery::discover` for the `edge` row, or label it "not tested (cfrs doctor tests it)" with a non-pass status. A check that cannot fail is not a check.
````

<a id="278"></a>

## #278: warp: four lifecycle and security gaps (half-installed routes, resolv.conf unlink, UDP ASSOCIATE takeover, unbounded inbound queue)

Opened 2026-11-04T03:44:01Z by `aerrand-agent`. State: open. Labels: none.

````markdown
## Summary

Four WARP lifecycle and security gaps. Each is read in the code; the TUN and `/etc/resolv.conf` paths could not be run here (no `CAP_NET_ADMIN`, and the file is system-owned).

Environment: cfrs 0.3.0-beta.11 (HEAD `9040b5b`), Debian 13, x86_64, uid 1000, no `CAP_NET_ADMIN`, `/dev/net/tun` exists but `TUNSETIFF` returns EPERM.

### 1. A failed second default route leaves the first half installed (minor)

`Routes::up` (`src/warp/route.rs:470-484`) uses `?` on each `route4`, and sets `self.up = true` only after the loop. `down` (`:489-501`) returns at once when `up` is false. If `0.0.0.0/1` is added and `128.0.0.0/1` fails, the error path leaves `0.0.0.0/1` pointed at the TUN after the process exits. Issue 77 is closed; this failure path remains.

Set `self.up = true` before adding, so `down` always attempts both halves, or delete the half already added on the error path.

### 2. `set_dns` unlinks `/etc/resolv.conf` before writing (minor)

`src/warp/route.rs:583-588` reads the backup, unlinks the file, then writes. If the write fails, the caller (`:452`) returns `Err` with `dns: None`, so `Drop` skips the restore. The host loses DNS.

Write a temporary file in `/etc` and rename it over `RESOLV`, keeping the backup in `Routes` before the first change.

### 3. A SOCKS5 UDP ASSOCIATE takes its client from the last datagram (minor)

`src/warp/proxy.rs:770` sets `*client = Some(from)` for every datagram, and the return path (`:786-798`) sends every tunnelled reply to that address. Any local process that sends one datagram to the ephemeral relay port becomes the client and receives the traffic. The SOCKS5 and `--proxy-user` authentication guards only the TCP control connection.

Set the client only when it is `None` (or equals `from`), and drop datagrams from any other address.

### 4. UDP ASSOCIATE advertises `127.0.0.1` to a remote client (minor)

`src/warp/proxy.rs:734-755` always binds the relay to `127.0.0.1` and reports that address in BND.ADDR. With `--listen tcp://0.0.0.0:PORT` and credentials, a remote client is told to send its datagrams to `127.0.0.1` on its own machine, so UDP through the proxy is broken for every non-local client. Issue 114 is closed; it covers hosts that refuse loopback, not remote clients.

Bind the relay on the address the control connection arrived on and report it, or refuse UDP ASSOCIATE for a non-loopback peer with a clear message.

### 5. The inbound queue from the tunnel is unbounded (minor)

`LinkDevice::tunnel_bounded` caps only `tx` (`src/vnet/device.rs:254`); `rx` is `PacketQueue::unbounded()` (`:268`). The WARP receive loop pushes every packet from the edge into `rx` (`src/warp/ip.rs:522`). A peer that sends faster than smoltcp consumes grows the heap for the life of the session. Issue 123 bounded a different buffer.

Give `rx` a capacity too, and count its drops as `tx` does.

## Dev work

Five contained changes, each with a unit test where the path allows. Items 1 and 2 need a fault injection for the route and write failure; items 3 and 4 can be tested on loopback.
````
