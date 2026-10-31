# Security

## Report a vulnerability

Do not open a public issue for a vulnerability. Use the private report of
GitHub: open <https://github.com/Azathothas/cfrs/security/advisories/new>
and write these items:

* the version (`cfrs --version`) and the system (`cfrs status`);
* the steps that show the fault;
* what an attacker can do, and what the attacker must have first.

The maintainer replies in the report. A fix comes in a new release, and the
report becomes a public advisory after the release.

## Supported versions

Only the latest release and `main` get fixes. A prerelease (a tag with a
suffix, for example `v0.3.0-beta.1`) is replaced by the next release.

## Dependencies

* `.github/workflows/deny.yml` runs `cargo deny` on each push and each day:
  advisories, licenses, bans and sources (`deny.toml`).
* An advisory stops CI. Update the crate, or replace it. If no fixed version
  exists and cfrs does not use the affected part, add the advisory to
  `[advisories] ignore` in `deny.toml` with the reason and the date it was
  read.
* Dependabot opens the updates of crates, actions and images each week.

The release files have checksums, provenance and a signature. See "Release
binaries" in `README.md`.

## What Cloudflare can see

* TLS between the visitor and the tunnel ends at the Cloudflare edge. The
  edge sees each request and each response of the origin in clear text.
* The hostname of a quick tunnel (`*.trycloudflare.com`) is public. Anyone
  who has the URL can send requests to the origin. A quick tunnel has no
  access control. `cfrs share` adds a PIN with `--password` (and always in
  proxy mode). `cfrs serve` and `cfrs tunnel` add nothing.
* `cfrs serve` and `cfrs share` publish files to the internet. Serve only
  the files that you want to give to all users.
* The WARP service sees the destination, the time and the volume of each
  connection that goes through WARP, and the content of each connection that
  has no TLS of its own.
* The edge, the quick-tunnel service and the WARP API see the public IP
  address of the host.

## What listens

cfrs listens only when a command asks for it. A tunnel connects out to the
edge; it does not listen. The commands below listen:

| Command | Default address | Who can connect |
| --- | --- | --- |
| `cfrs warp proxy` | `tcp://127.0.0.1:40000` | Each user of the host (loopback TCP). Use `--listen unix:/path` for the owner only. |
| `cfrs net proxy` | `unix:/tmp/cfrsnet.socks` | The owner only (socket mode 0600). |
| `cfrs net switch` | `unix:/tmp/cfrsnet.switch` | The owner only (socket mode 0600). |
| `cfrs net tailscale` | `unix:/tmp/cfrssocks.sock` | The owner only (socket mode 0600). |
| `cfrs connect -L` | no default | `tcp://port` binds `127.0.0.1`. A Unix socket has mode 0600. |
| `pod-netns --serve` | no default | A Unix socket has mode 0600. A TCP address is open to each user who can reach it. |
| `cfrs pod`, `cfrs warp run` (seccomp backend) | `/tmp/pod-netns-inbound/<port>.sock` | The owner only (socket mode 0600). One socket for each port that the program listens on. |

A TCP address that is not a loopback address is open to the network. cfrs
does not refuse it, because some hosts permit no other listener.

`tests/cli.rs` (`the_listen_defaults_agree_with_the_manual`) checks the
defaults in this table against `cfrs man --json`.

## Secrets

| Secret | Where cfrs keeps it |
| --- | --- |
| Named-tunnel token and secret | In memory only. Give it in `TUNNEL_TOKEN`, a config file or a cloudflared credentials file. `--token` also works, but other users of the host can read a command line. |
| WARP device token, MASQUE private key, WARP+ license | The identity file (`cfrs man files`), mode 0600, in a directory with mode 0700. cfrs writes it to a new file and then renames it. cfrs refuses an identity file that belongs to another user, or that the group or other users can read. |
| Proxy user and password | In the proxy variables or `-x`. |

These rules apply to each secret:

* No log line, error line or failure report holds it. The `Debug` text of
  `Credentials`, the WARP `Device` and `Account`, and `Proxy` shows
  `<hidden>`. Each error line and each line of the failure report goes
  through `report::mask`, which hides the user and the password of each URL,
  the value of each proxy variable, and the token.
* `tests/cli.rs` (`the_log_holds_no_secret`) runs cfrs with `RUST_LOG=trace`
  and a token, a WARP identity and a proxy password. The test fails when one
  of them is in the output.

## Text from the network

Text from a peer (an edge error, an HTTP body, a proxy reply) can hold
control characters that a terminal acts on. `report::clean` removes each
escape sequence, BEL, CR, and the other control characters except tab and
line feed. Each error line and the failure report go through it. The log
writer (`tracing-subscriber`) escapes control characters in the log fields.
A test (`report::tests::the_error_line_has_no_control_characters`) sends
ESC, BEL, CR and C1 controls through the error path.

## Known gaps

* No third party has audited cfrs.
* The Cap'n Proto encoding, the RPC subset, the HTTP/2 edge transport, the
  MASQUE client and the YAML reader are written for cfrs. The fuzz tests of
  issue #5 are not done yet.
* With no `XDG_STATE_HOME` and no `HOME`, the WARP identity file is
  `cfrs-warp.json` in the current directory.
* The `/tmp` paths of the Unix sockets are known to each user. Another user
  can make the path first. Then the bind fails; cfrs does not use the file of
  the other user. Use `--listen unix:` with a path in a private directory.
