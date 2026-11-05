The deferred GitHub issues: the owner keeps each one open, and each entry
waits for the owner or for a condition outside the repository
(`docs/decisions.md`, "Deferred issues"). The Problem of each entry keeps
the text of its issue that the work needs.

# T-001: Tracking: dev work in a sandbox with basic networking, and launch once and forget (GitHub #89)

**Source:** GitHub #89, the tracking issue of the owner.
**Category:** chore
**Milestone:** M9
**Priority:** P3
**Effort:** S
**Status:** blocked

## Problem

The goal of the issue: "A sandbox with basic networking (an allowlisted
HTTPS proxy only, or TCP 80/443 only, no UDP, no IPv6, no root) gets
working dev networking from one command, and cfrs runs in the background
with no further care."

The rulings in the issue: MASQUE through the WebSocket relay with an
automatic fallback (`--no-relay` turns it off); later shells join through
`cfrs warp env`, a `--persist` shell hook, `cfrs warp exec` and
`cfrs warp shell`; detached instances restart by default and record a new
quick-tunnel URL; tests of network paths run on GitHub runners
(`.github/workflows/live.yml`), not through a way around the policy of a
sandbox.

The items of the issue are #70 to #88: detach with a ready document,
the instance registry, `ps`/`stop`/`logs -f`/`wait`, the supervisor,
autostart, the WARP reconnect, MASQUE through the relay, pod loopback and
UDP, later shells, `warp up` with root, netns raw IP with no root, IPv6,
`doctor --agent`, `warp nc`, the CA bundle inside WARP, proxy detection
and Digest, UDP with no kernel `AF_INET` bind, the reverse relay, and
`cfrs agent up`. GitHub has each of them closed.

## Premise

Read: the issue and its comments, and `docs/decisions.md`. A tester ran
`cfrs agent up` end to end on a host of the target class with
0.3.0-beta.6 (no root, no TUN, TCP bind refused, TCP egress 80/443 only):
WARP registration, the detached `warp proxy` on a Unix socket, then
`warp exec`, `warp shell` and `warp nc`. Not measured in this sandbox.

## Approach

1. Make each new request of the goal an entry of its own, with the
   Source `GitHub #89`.
2. When the owner closes the issue, write `## Done` with the state of the
   issue as the evidence.

## Prove

```sh
curl -qfsS "https://forge.web.pkgforge.dev/github/repos/Azathothas/cfrs/issues/89?n=$RANDOM" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])'
```

The command prints `closed`.

## Blocker

The owner. The ruling "Deferred issues" of 2026-11-04 in
`docs/decisions.md` keeps the issue open as the tracking issue of the
owner. The entry is unblocked when the owner closes the issue, or names
the work that remains.

# T-002: `warp proxy --l4`: the L4 door answers 403 to each form of the CONNECT (GitHub #140)

**Source:** GitHub #140.
**Category:** feature
**Milestone:** M9
**Priority:** P2
**Effort:** M
**Status:** blocked

## Problem

The issue: each TCP client of `cfrs warp proxy` becomes IP packets in the
userspace stack over one CONNECT-IP stream. Each flow has TCP buffers of
512 KiB in each direction, all flows share one driver task and one HTTP/2
stream window, and a name costs two DNS queries in the tunnel before the
connect. The issue asks for `warp proxy --l4`: one HTTP/3 `CONNECT` stream
for each TCP client to the L4 door of WARP (UDP 443, TLS name
`consumer-masque-proxy.cloudflareclient.com`), with no IP stack. The name
goes in `:authority`, so the service resolves it. UDP is not carried in
this mode.

The client side is in `src/warp/l4.rs` (commits `9d30496`, `81e56d0`,
`3e1e1a3`; the rules apply to `--l4` from `db6dbe6`; clap refuses `--l4`
with `--dns` or `--listen-identity`). The live runs show that QUIC, TLS
and the pinned key of the device work with the TLS names
`consumer-masque-proxy.cloudflareclient.com` and
`consumer-masque.cloudflareclient.com`. The door answers 403 to each
CONNECT, in each of three forms (`CFRS_WARP_L4_FORM`):

- `plain`: `:method CONNECT`, `:authority host:port` (RFC 9114,
  section 4.4);
- `extended`: `:protocol cf-connect-tcp` with `:scheme` and `:path`
  (RFC 9220);
- `header`: a plain CONNECT with `cf-connect-proto: cf-connect-tcp`.

## Premise

Read: `src/warp/l4.rs`, `src/warp/proxy.rs`, and the report of the three
forms in `scripts/live-batch2.sh`. `docs/protocol.md` says that the L4
proxy mode of the front door is HTTP/3 only. Not measured here: this
sandbox cannot reach WARP. The door knows the device and refuses the
request. Possible causes: an anonymous consumer device has no right to
the L4 door, or the door wants a form that is not one of the three.

## Approach

1. Get one captured request of an official client in proxy mode: the
   pseudo-headers and the headers, with the secrets replaced.
2. Send that form from `src/warp/l4.rs`, and add a loopback test of the
   field section of that form.
3. Make the `--l4` report of `scripts/live-batch2.sh` a check: a download
   through the door gets HTTP 200.

## Prove

```sh
cargo test -p cfrs --lib warp::l4
```

Then the `--l4` step of `scripts/live-batch2.sh` in a run of
`.github/workflows/live.yml` prints HTTP 200 for the download through the
door.

## Blocker

A captured request of an official client in proxy mode. A tester or the
owner gives it. The ruling "#140" of 2026-11-04 in `docs/decisions.md`
keeps the issue open until it comes.

# T-003: `warp register`: enrol through a Zero Trust team token (GitHub #149)

**Source:** GitHub #149.
**Category:** feature
**Milestone:** M9
**Priority:** P2
**Effort:** S
**Status:** blocked

## Problem

`src/warp/register.rs` creates an anonymous consumer device only; the
requests have no field for a team credential. An organization that runs
Zero Trust cannot enrol a host with cfrs: the device must come from the
dashboard or the official client, and the front-door name must be set by
hand (`--masque-sni`) on each command. `Account` has `id`,
`account_type` and `license` only, so a managed account prints as a
consumer account with no licence.

The proposal of the issue:

- Flags: `--team-token TOKEN` (`CFRS_WARP_TEAM_TOKEN`; hidden from `ps`
  and the logs), `--team-token-file PATH` (`CFRS_WARP_TEAM_TOKEN_FILE`,
  mode 0600), `--team-sni NAME` (`CFRS_WARP_TEAM_SNI`; default: the host
  of the `iss` of the token). The two token forms conflict with each other
  and with `--ephemeral`. With an existing identity file, the flag has no
  effect (one debug line).
- Parse the token locally (a JWT: `iss`, `aud`, `exp`; no signature
  check). A malformed or expired token exits 78 before a network call, and
  the message gives the expiry date. Another refusal of the API exits 69.
- Send the token only on the `POST /reg` of a new device. The issue
  proposes the header `CF-Access-Jwt-Assertion`.
- The MASQUE TLS name of a team device defaults to `zt-masque.DOMAIN`;
  `--masque-sni` has priority.
- `Account` gets `managed` and `organization`; the identity file records
  `"team": {"domain": ..., "enrolled_at": ...}` and never the token.
  `warp license` on a managed device exits 78 with the reason.
- `--ephemeral` with `--team-token` exits 64.

## Premise

Read: `src/warp/register.rs`. The enrolment through a team token is not
documented. cfrs has no Zero Trust organization to test with. A wrong
request can register devices that a team does not want. The header name
of the proposal is not measured.

## Approach

1. Get a captured exchange of the official client against a test team:
   the request and the answer of the team token step (the path, the
   headers without the token, the JSON body with the secrets replaced),
   and the `POST /reg` request and answer of that device.
2. Add the flags to `cfrs warp register`. Keep the anonymous path as it
   is.
3. Test the parse of the token, the header and the exit codes against a
   loopback API stand-in (`CFRS_WARP_API`).

## Prove

```sh
cargo test -p cfrs --lib warp::register
```

## Blocker

A captured exchange of the official client against a test Zero Trust
team. A tester or the owner gives it. The ruling "#149" of 2026-11-04 in
`docs/decisions.md` holds the work until it comes.

# T-004: TLS: send an encrypted ClientHello on the hops that publish a config (GitHub #151)

**Source:** GitHub #151.
**Category:** feature
**Milestone:** M9
**Priority:** P3
**Effort:** M
**Status:** blocked

## Problem

Each TLS connection of cfrs sends the server name in the clear. The
builders are `client_config` in `src/trust.rs` (the WARP API, the edge
legs, the relay), `tls_config` in `src/warp/session.rs` (MASQUE, with the
pinned key) and `client_config` in `src/cloudflare/quic.rs` (QUIC to the
edge). None of them enables ECH.

The proposal of the issue: `--ech auto|off|CONFIG` (`CFRS_ECH`, default
`off`), `--ech-front NAME` (default `cloudflare-ech.com`),
`--ech-hops LIST` (`api,edge,masque`), `--ech-allow-plaintext`,
`--ech-grease`. Fetch the config from the HTTPS record (type 65) through
the DoH client and cache it with its TTL. Refuse a name that is longer
than the `max_name_length` of the config, with both numbers in the
message. Retry once with the retry configs of a rejection. Report the ECH
status of each hop in `doctor`. The ClientHello stays the same with ECH
off.

A limit: the public config of `cloudflare-ech.com` has
`max_name_length` 18, and the MASQUE name
`consumer-masque.cloudflareclient.com` has 36 characters.

## Premise

Read: `src/trust.rs`, `src/warp/session.rs`, `src/cloudflare/quic.rs`.
ECH needs HPKE. The crypto provider of cfrs is ring, which has no HPKE.
The HPKE of rustls is in the aws-lc-rs provider (a C build on each of the
8 targets) or in another crate. The MASQUE front door and the WARP API
publish no ECH config that cfrs can use, so ECH changes nothing on them.
Done in place of ECH: the ClientHello of MASQUE can be split into records
(#135, commit `b811b8e`), and the session can go over HTTP/3 or WireGuard
(#157, #152).

## Approach

1. Look for an `ech=` parameter in the HTTPS records of the hops that
   cfrs uses.
2. When a hop publishes a config: write a client HPKE over ring (X25519,
   HKDF-SHA256, AES-128-GCM) with the test vectors of RFC 9180, then add
   `--ech` (off by default) for that hop.

## Prove

```sh
cargo test -p cfrs --lib ech
```

## Blocker

A hop of cfrs must publish an ECH config, and the owner must accept an
HPKE provider. The ruling "#151" of 2026-11-04 in `docs/decisions.md`
defers the work.

# T-005: crates.io: publish the library and the CLI (GitHub #161)

**Source:** GitHub #161 (from #160, item K3).
**Category:** release
**Milestone:** M9
**Priority:** P2
**Effort:** S
**Status:** blocked

## Problem

`Tunnel`, `WarpClient` and the userspace network stack are public API of
the library crate. The issue asks to publish the CLI and `pod-netns` on
crates.io. Facts of the issue:

- The name `cfrs` on crates.io belongs to another project (T-007).
- A publish needs a crates.io token as a secret of the repository, and a
  manual step in the release (or a `publish` input).
- `pod-netns` is a path dependency. It must be published first, with the
  same version.

## Premise

Read: `Cargo.toml`, `crates/pod-netns/Cargo.toml`, and the step "Package
lists" of `.github/workflows/ci.yml`. The packaging defects that a publish
shows are fixed (commit `6080d99`), and CI runs `cargo package --list` for
both crates.

## Approach

1. The owner chooses a package name (T-007).
2. Set the stable version (T-006).
3. Add a crates.io token as a secret, and a publish step to
   `.github/workflows/release.yml`: `pod-netns` first.

## Prove

```sh
cargo publish --dry-run --locked -p pod-netns
cargo publish --dry-run --locked -p cfrs
```

## Blocker

The owner. The ruling "crates.io" of 2026-11-04 in `docs/decisions.md`:
publish nothing now, and choose no package name; decide again at the
stable release.

# T-006: crates.io: the workspace version and the `pod-netns` requirement are prereleases (GitHub #222)

**Source:** GitHub #222.
**Category:** release
**Milestone:** M9
**Priority:** P2
**Effort:** S
**Status:** blocked

## Problem

`Cargo.toml` has the workspace version `0.3.0-beta.12`, and the
dependency `pod-netns` requires `0.3.0-beta.12`. crates.io marks a version
with a pre-release identifier as a prerelease: it does not satisfy
`^0.3.0`, and `cargo install` skips it unless `--version` names it. A
requirement `^0.3.0-beta.N` matches only prereleases, so it does not match
a stable `pod-netns` `0.3.0`. The first stable version is `0.3.0`. Change
the workspace version and the requirement in one commit. The release
notes tell the users who pinned `=0.3.0-beta.N` to change to `0.3.0`.

## Premise

Read: `Cargo.toml`. `cargo publish --dry-run` does not find either
problem: crates.io decides at the upload.

## Approach

At the first stable release, in one commit: set the workspace version and
the `pod-netns` requirement to `0.3.0` (step 1 of "Release" in
`docs/maintenance.md`), and write the note in the release notes.

## Prove

```sh
grep -n '^version = "0.3.0"$' Cargo.toml
cargo package --locked --list -p pod-netns
```

## Blocker

The owner: the first stable release. The ruling "Deferred issues" of
2026-11-04 in `docs/decisions.md` keeps the issue open until that release.

# T-007: crates.io: the name `cfrs` belongs to another project; choose a package name (GitHub #224)

**Source:** GitHub #224.
**Category:** release
**Milestone:** M9
**Priority:** P2
**Effort:** S
**Status:** blocked

## Problem

The crate `cfrs` on crates.io is a different, older project (created
2024-04-14, version 1.1.0). `cargo publish --dry-run` does not find a name
collision. A publish needs a new package name (the binary keeps its name
through `[[bin]] name`), or a transfer of the name through crates.io
support. The same commit changes the install text of `README.md`, the
program-name strings of the CLI, the cross-references of
`crates/pod-netns/README.md`, and adds a crates.io install section
(`cargo install NAME`, `cargo add`) and a docs.rs badge to `README.md`.

## Premise

Read: the answer of `https://crates.io/api/v1/crates/cfrs` that the issue
quotes. Not measured here.

## Approach

1. The owner chooses a package name.
2. In one commit: set `[package] name`, keep the binary name, and change
   the texts of the Problem.

## Prove

```sh
cargo package --locked --list -p NAME
```

## Blocker

The owner chooses a package name. The ruling "crates.io" of 2026-11-04 in
`docs/decisions.md`: choose no package name now.
