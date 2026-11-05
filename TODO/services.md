This file holds the entries of milestone M6: the services that podnet builds from its pieces. The
order is the owner's (2026-11-05): the shared parts first, then the file server, git hosting, the
router, and file transfer. `docs/research/podnet/capabilities.md` gives the design of each role.
`docs/research/podnet/podssh-copy.md` gives the podssh code that podnet copies, and how. A copy
of podssh code lands in one commit ("Copy podssh PATH at COMMIT into PATH"), and its changes in
later commits.

# T-082: `connect --stdio` for an SSH `ProxyCommand` through `tunnel --forward`

**Source:** `docs/research/podnet/capabilities.md`, sections 1.1 and 6 (enabler 1).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

`connect` has `-L` listeners only. An SSH `ProxyCommand` through `tunnel --forward` needs a
stream on stdin and stdout. Git over SSH through the tunnel needs it.

## Premise

- Read: `-L` is required in `ConnectArgs` (`src/main.rs`).
- `relay connect` has a mode on stdin and stdout already (`src/relay_reverse.rs`).
- `src/ws.rs` holds the WebSocket client of the forward.

## Approach

1. Add `connect URL --stdio`: one stream, stdin to the WebSocket and the WebSocket to stdout.
2. Exit at the end of either side. Take the Basic credentials as `-L` does.

## Prove

```sh
cargo test --test connect -- connect_stdio_carries_a_stream
```

The test runs a WebSocket forward on the loopback and pipes bytes through `connect --stdio`.

# T-083: A relay node serves a handler in the process, with no socket file

**Source:** `docs/research/podnet/capabilities.md`, section 6 (enabler 2).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

`relay node` serves one target: a TCP address or a unix socket. A file server, a git SSH server or
a transfer in the same process must open a socket file to be reached.

## Premise

- Read: `Target` has the variants `Tcp` and `Unix` (`src/relay_reverse.rs`).
- `tests/relay_reverse.rs` runs a node against a fake relay.

## Approach

1. Add a target that calls a handler with the stream of each session.
2. Use it for the file server (T-091), git (T-094) and the transfer (T-104).

## Prove

```sh
cargo test --test relay_reverse -- a_node_serves_an_in_process_handler
```

# T-084: One HTTP authentication layer for the local listener, the tunnel and the relay

**Source:** `docs/research/podnet/capabilities.md`, sections 3.2 and 6 (enabler 3).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

HTTP Basic authentication lives only in the dispatch of the tunnel, and `serve --local` refuses
it. The PIN gate works only for `share`. A service on a local listener or a relay node has no
authentication.

## Premise

- Read: the Basic check is in `src/proxy.rs`, and its credentials in `src/proxy_auth.rs`
  (`Credentials`).
- Read: `serve --local` refuses `--auth-user` (`src/main.rs`).
- The PIN gate is `src/gate.rs`.

## Approach

1. Write one axum layer over `Credentials` and the gate, with the roles read and write.
2. Use it in the tunnel, on the local listener and on the relay node.
3. Let `serve --local` take `--auth-user` and `--auth-password-file`.

## Prove

```sh
cargo test --workspace -- auth_layer_ serve_local_takes_basic_auth
```

With no credentials the answer is 401. A PUT of a read user is 403. The same layer works on a
unix-socket listener.

## Start condition

T-062 is done.

# T-085: A ustar writer and reader, and a directory as one tar download of the file server

**Source:** `docs/research/podnet/capabilities.md`, sections 3.1, 3.4 and 6 (enabler 6).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

podnet has no tar writer or reader. The file server cannot give a directory as one download.

## Premise

- No crate of the lock gives tar today, and the design needs none (about 250 lines).
- `src/service.rs` holds the static router and its guard.

## Approach

1. Write a ustar writer and reader in `podnet-serve`: regular files and directories, long names
   with the ustar prefix, no link out of the root.
2. With `--tar`, the file server gives a directory as one tar stream.

## Prove

```sh
cargo test -p podnet-serve -- ustar_round_trip_keeps_odd_names a_directory_downloads_as_a_tar
```

The second test compares `tar -tf` of the download with the tree.

# T-086: Copy the resumable layer, the end-to-end channel, the key identity and UDP in a stream of podssh into `podnet-relay`

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.3, 3 (C4, C6, C7) and 5 (G1);
`docs/research/podnet/capabilities.md`, section 6 (enabler 5).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

The relay closes a session at 64 MiB in each direction, after 12 h, or after 180 s with no
traffic. podnet has no resume, so a clone, a push or a transfer over the relay that is larger
fails. The relay sees the bytes.

## Premise

- podssh has a resumable layer (`Azathothas/podssh:crates/podssh-relay/src/session/`, 7,468
  lines, 6,820 with no handover), an end-to-end channel on Noise XX (its core, about 1,700
  lines), a key identity (694 lines) and UDP in a stream (352 lines).
- A trial built the layer alone with three shims. 135 tests of 18 test files passed.
- The only new crate of the layer is `x25519-dalek 3`. `snow 0.10` brings the older RustCrypto
  line, with about 10 warnings of duplicate versions.

## Approach

1. Copy the layer with no `handover/` and no `keep/handover.rs`, with the shims `text.rs`,
   `wake.rs` and the backoff helper.
2. Change in later commits: the `PODSSH_*` variables to `PODNET_*`, with rows in
   `src/manual/facts.rs`; Linux only; `cargo fmt` at width 100; split each file over 800 lines;
   a podssh id in a comment as "podssh T-NNN"; no dated history in comments.
3. Copy the core of the channel (`mod.rs`, `frame.rs`, `channel.rs`, `channel/carry.rs`,
   `handshake.rs`, `ends.rs`, `ask.rs`) and the identity, with ed25519-dalek 3 and the
   private-file helpers of podnet. Then copy UDP in a stream.
4. Copy the tests with the code: the 18 self-contained session test files, and the tests of the
   channel and of the identity file.
5. Run `cargo deny check`.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Code of podssh and Crypto crates): copy podssh code
and change it as necessary; no wire compatibility with podssh is promised. `snow` 0.10 is
accepted. `cargo deny` stays green with no ignored advisory.

The owner, 2026-11-05 (`docs/decisions.md`, Shared crates): the shared crates of `PodUtils/podcrates` hold this code. podnet depends on the shared crate; it does not copy the code.

## Prove

```sh
cargo test -p podnet-relay
cargo deny check
gh workflow run release.yml --ref main   # the dry run builds the eight targets
```

## Start condition

T-049 is done.

The shared crates exist in `PodUtils/podcrates` (T-137; the ruling "Order" of 2026-11-05 in `docs/decisions.md`).

# T-087: `relay node` and `relay connect` resume a session past the limits of the relay

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.3, 3 (C5) and 5 (G2).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A session through the relay ends at its byte or time limit, and the stream breaks. Git over the
relay and the transfer need more than 64 MiB.

## Premise

- Both ends of the reverse road are podnet, so the layer of T-086 can run for each session above
  the framing of `src/relay_reverse.rs`.
- The forward road (`warp nc --via-relay`, the leg http2+relay, MASQUE through the relay) ends at
  the relay Worker. It cannot resume, and it reconnects as today.

## Approach

1. The node runs the far end of the layer for each session.
2. `relay connect` runs the client of the layer, with a link maker that opens
   `/v1/connect/NAME` again.
3. Move to a second link before 48 MiB or 11 h. Print each move with `-v`. Warn before the pair
   expires.
4. Run the layer alone first. Add the end-to-end channel with keys (`--key`, `--allow`) as an
   option, and ask the owner whether it is the default.

## Prove

```sh
cargo test --test relay_reverse -- relay_session_moves_past_the_cap
gh workflow run live.yml
```

A fake relay with a cap of 1 MiB carries 8 MiB in each direction with equal SHA-256. The live
step carries 200 MiB in each direction through the real relay.

## Start condition

T-086 is done.

# T-088: File server: a directory listing in HTML and JSON

**Source:** `docs/research/podnet/capabilities.md`, sections 3.1 to 3.5.
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

`serve` gives 404 for a directory with no `index.html`. A user cannot see the files of a
directory.

## Premise

- Read: the static router and its guard are in `src/service.rs`. The guard refuses a dot segment
  and a path out of the root.
- `src/gate.rs` has `escape_html`.

## Approach

1. Move the static router and its guard to a files module of `podnet-serve`.
2. Add a listing in HTML (each name escaped) and in JSON (with `Accept: application/json`).
3. Hide the dotfiles and each link out of the root.

## Prove

```sh
cargo test -p podnet-serve -- a_listing_escapes_names_and_hides_dotfiles a_listing_in_json
```

A name with `<script>` is escaped in the HTML listing.

## Start condition

T-062 is done.

# T-089: File server: users with read and write roles, and a PIN, on each listener

**Source:** `docs/research/podnet/capabilities.md`, sections 3.1 to 3.3.
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

`serve` has one Basic user, through the tunnel only. It has no roles and no PIN.

## Premise

- The layer of T-084 gives Basic users and the PIN gate on each listener.

## Approach

1. Add `--users FILE`: lines `USER:ROLE:HASH`, or `USER:ROLE` with a password file. The roles are
   read and write.
2. Add `--pin` (the gate of `share`) and `--anon-read`.

## Prove

```sh
cargo test -p podnet-serve -- serve_users_have_roles serve_pin_unlocks
```

## Start condition

T-084 is done.

# T-090: File server: uploads into the served tree with PUT and a multipart form

**Source:** `docs/research/podnet/capabilities.md`, sections 3.1 to 3.5.
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A user cannot upload into the served tree. `share --mode upload` writes to its own directory with
random names.

## Premise

- Read: `upload_receive` streams a multipart body with limits and files of mode 0600
  (`src/share.rs`).
- The tunnel takes at most 100 MB in one request body.

## Approach

1. Accept PUT (`curl -T`) and a multipart form into the tree, for the write role.
2. Write to a temporary file, then rename it. Reuse the streaming core of `upload_receive`.
3. Answer 413 before the body when it is over `--max-upload`, and leave no partial file.
4. Refuse `..` and each dot segment.

## Prove

```sh
cargo test -p podnet-serve -- put_into_the_tree_is_atomic_and_bounded
```

A PUT gives 201. A PUT over the limit gives 413 and leaves no file. A PUT with `..` is refused.

## Start condition

T-089 is done.

# T-091: `podnet serve DIR --via`, a local `share`, a directory in `share`, and the live step of the file server

**Source:** `docs/research/podnet/capabilities.md`, sections 3.2, 3.3 and 3.5.
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

`serve` reaches users through a tunnel or a local listener only. `share` has no local listener.
`share --mode download` takes one regular file only.

## Premise

- The relay exposure works today only by a composition of three commands
  (`docs/research/podnet/capabilities.md`, section 3.2).
- T-083 gives a node a handler in the process. T-085 gives a tar stream.

## Approach

1. Give `serve` the form `podnet serve DIR [--local ADDR]... [--via tunnel, relay or none]`, with
   `--list`, `--upload`, `--tar` and the flags of authentication.
2. `--via relay` serves through a relay node with the handler of T-083.
3. Add `share --local ADDR`, and a directory in `share --mode download` as a tar stream.
4. Extend the live step "Quick tunnel with --auth-user": the listing, a range, a PUT of 1 MiB and
   a 401; then the same through the relay.

## Prove

```sh
cargo test --test cli -- serve_dir_with_list_upload_and_users share_local_serves_a_directory
gh workflow run live.yml
```

## Start condition

T-083, T-085, T-088, T-089 and T-090 are done.

# T-092: Git: a CGI runner for `git http-backend`, and the smart HTTP router

**Source:** `docs/research/podnet/capabilities.md`, sections 5.2, 5.3 (design A) and 5.8; the
owner's ruling of 2026-11-05 (`docs/decisions.md`, Git hosting).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

podnet has no git server. A host behind a proxy cannot serve a repository to others.

## Premise

- `git http-backend` serves the smart HTTP protocol as a CGI program.
- `tokio` has the feature `process` (`Cargo.toml`).
- `git http-backend` inflates a body with `Content-Encoding: gzip`. A chunked body works with git
  2.19 or later; a test must confirm the minimum version.
- `src/proxy.rs` streams the body of an axum router behind the tunnel.

## Approach

1. Write a generic CGI runner: the environment (`GIT_PROJECT_ROOT`, `PATH_INFO`,
   `REQUEST_METHOD`, `QUERY_STRING`, `CONTENT_TYPE`, `CONTENT_LENGTH` unset for a chunked body,
   `GIT_HTTP_EXPORT_ALL`, `HTTP_GIT_PROTOCOL`, `REMOTE_ADDR`, and `REMOTE_USER` only after a good
   authentication). Parse the CGI head (`Status:`). Stream the body in both directions.
2. Write an axum router: anonymous clone and fetch; 401 for `service=git-receive-pack` with no
   credentials, so that git asks for them; protocol v2.
3. Refuse `..`, each dot segment and `/.git/config`.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Git hosting): `podnet git serve` uses the installed
`git` now (`git http-backend`). A native server comes later (T-122).

## Prove

```sh
cargo test --workspace -- git_http_clone_fetch_and_push
```

The test is skipped, with one line, when `git` is not on `PATH`. It clones, fetches with protocol
v2, and pushes with credentials. An anonymous push and a wrong password give 401. `/../` is
refused. A push of 8 MiB with `http.postBuffer=1024` (a chunked body) and an upload-pack request
over 1 KiB (a gzip body) pass.

## Start condition

T-084 is done.

# T-093: Git: an SSH server for upload-pack and receive-pack

**Source:** `docs/research/podnet/capabilities.md`, sections 1.5, 5.4 and 5.8;
`docs/research/podnet/podssh-copy.md`, sections 2.7 and 3 (C22); the owner's ruling of 2026-11-05
(`docs/decisions.md`, Git hosting).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

podnet has no SSH server. The server module of russh is compiled in, and nothing calls it.

## Premise

- `russh 0.64` is a dependency with the feature `ring` and no `rsa` (`Cargo.toml`).
- `ssh-key` parses an `authorized_keys` file (`AuthorizedKeys`).
- podssh has a russh 0.65 server for its tests
  (`Azathothas/podssh:crates/podssh-cli/tests/ssh_harness/`), and no server in its product.
- The `rsa` feature brings an advisory (RUSTSEC-2023-0071), and `deny.toml` ignores none.

## Approach

1. Make an ed25519 host key once. Keep it in the state directory with mode 0600.
2. Check `auth_publickey` against the `authorized_keys` file. With `--anon-read`, `auth_none`
   gives read access only.
3. Keep `GIT_PROTOCOL` from `env_request`. Accept in `exec_request` only `git-upload-pack 'PATH'`,
   `git-receive-pack 'PATH'` and `git-upload-archive 'PATH'`. Run git, pump stdin, stdout and
   stderr, and send the exit status.
4. Refuse a shell, a pty, `direct-tcpip` and `tcpip-forward`.
5. Take ed25519 and ECDSA keys only.
6. Copy parts of the test server of podssh as an SSH server for the tests.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Git hosting and Crypto crates): upload-pack and
receive-pack under a russh SSH server; `cargo deny` stays green with no ignored advisory, so no
RSA keys.

## Prove

```sh
cargo test --workspace -- git_ssh_upload_pack_matches_git git_ssh_refuses_an_unknown_key
```

The russh client of the tree runs `exec git-upload-pack` over a unix socket. Its ref
advertisement equals the output of `git upload-pack --advertise-refs`. An unknown command is
refused.

# T-094: `podnet git serve`: the repository root, `git init`, `git urls`, the tunnel, the relay and the live step

**Source:** `docs/research/podnet/capabilities.md`, sections 5.5 to 5.8.
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The parts of T-092 and T-093 have no command.

## Premise

- The quick tunnel takes at most 100 MB in one request body, so a larger push over HTTP fails.
  A clone is not limited.
- Until T-087, a clone or a push over the relay ends at 64 MiB.

## Approach

1. Add `podnet git serve --root DIR` with `--local ADDR`, `--ssh LISTEN`, `--via`,
   `--anon-read`, `--push-user` with `--push-password-file` or `--users FILE`,
   `--authorized-keys FILE`, `--create-on-push` and `--detach`.
2. Add `podnet git init NAME` and `podnet git urls` (the clone URLs and the fingerprint of the
   host key).
3. Map each request to a repository under the root. Refuse `..`.
4. Make `doctor` report a missing `git`. Write the limits in the manual.
5. Add a live step: through a quick tunnel, a clone and a push over HTTPS with credentials, and
   an anonymous push refused; through a relay node and `ssh -o ProxyCommand` with
   `relay connect NAME`, a clone and a push.

## Prove

```sh
cargo test --test cli -- git_serve_init_and_urls
gh workflow run live.yml
```

## Start condition

T-082, T-092 and T-093 are done.

# T-095: Router: several WARP identities in one process, each with its own counters

**Source:** `docs/research/podnet/capabilities.md`, section 2;
`docs/research/podnet/mwan-field.md`, sections 1.6 (mode A) and 2.2 (R1, R6).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

`warp proxy --listen-identity LISTEN=PATH` gives one listener for each device, but the counters
are global, and no other command can use a second device.

## Premise

- Read: `LINK_STATS` in `src/warp/ip.rs` and `STATS` in `src/warp/proxy.rs` are global.
- Each identity keeps its device in its own file, so a device is not registered again.

## Approach

1. Keep N identities in one process, each in its own directory of the state directory.
2. Make one WARP network for each identity, with its own counters.
3. Accept `--net NAME=warp:PATH` through the registry of T-059.

## Prove

```sh
cargo test --workspace -- two_warp_identities_keep_their_counters
```

The edge stand-in of T-012 serves two identities.

## Start condition

T-057 is done.

# T-096: Router: groups of networks with weights and a kill switch

**Source:** `docs/research/podnet/capabilities.md`, sections 2.1 and 2.5;
`docs/research/podnet/mwan-field.md`, sections 1.4 (D1) and 1.6; the owner's ruling of 2026-11-05
(`docs/decisions.md`, Router).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

podnet has no groups, no weights and no kill switch. The kill switch of the mwan experiment leaks
to the host route.

## Premise

- `docs/research/podnet/mwan-field.md`, section 1.6: a userspace router starts each flow again on
  one uplink, so it needs no kernel route, no masquerade and no `rp_filter`.
- Balancing is per flow. One flow uses one uplink.

## Approach

1. Add a `Balance` combinator: a weighted pick for each flow; the same member for each pair of
   client and destination of UDP; a member that is down leaves the pick.
2. When no member is healthy, refuse the flow. Never fall back to direct.
3. Accept `--group NAME=a*2,b*1`.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Router): the userspace router first, per flow, with no
`CAP_NET_ADMIN`: groups, weights, TCP health checks, failover and a kill switch.

## Prove

```sh
cargo test --workspace -- router_group_splits_by_weight_and_fails_closed
```

The unit tests pick with a seed. The loopback test runs two fake SOCKS5 upstreams.

## Start condition

T-058 is done.

# T-097: Router: a TCP health check for each member, and `podnet route status`

**Source:** `docs/research/podnet/capabilities.md`, sections 2.1 and 2.5;
`docs/research/podnet/mwan-field.md`, sections 1.4 (D5, D6, D10), 1.6 and 2.2 (R2, R5).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A group needs the state of each member. An ICMP check lies for a WARP session that carries no
TCP (T-068).

## Premise

- The probe of T-068 renews a WARP session that carries no TCP.
- `src/metrics.rs` and `src/decisions.rs` give counters and decision lines.
- The mwan experiment leaks a socket for each probe, keeps no round-trip time, and puts a link
  back after one good probe.

## Approach

1. Probe each member: a TCP connect to `HOST:PORT` through it, each N s. Close the socket. Keep
   the round-trip time.
2. Mark a member down after K misses, and up after R successes.
3. A failed probe of a WARP member calls the renew of T-068.
4. Add `podnet route status [--json]`: the state, the round-trip time, the flows and the bytes of
   each member. Add rows to the metrics.

## Prove

```sh
cargo test --workspace -- router_health_moves_flows_off_a_dead_member router_status_json_keys
```

## Start condition

T-096 and T-068 are done.

# T-098: Router: doors with a default network, and rules to a network, a group or a refusal

**Source:** `docs/research/podnet/capabilities.md`, sections 2.1 to 2.3.
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The rules of `warp proxy` have the actions tunnel, direct and reject only. A door cannot send a
flow through another network.

## Premise

- `src/warp/rules.rs` holds the rule actions. T-061 gives one door over a dialer.

## Approach

1. Add `--door LISTEN=NET` (a network or a group): SOCKS5, HTTP CONNECT, UDP ASSOCIATE and an
   optional DNS, on TCP or `unix:`.
2. Add rules `domain:` and `cidr:` to a network, a group or `reject`. The first match wins. A
   change of the rules file takes effect with no restart.

## Prove

```sh
cargo test --workspace -- router_rules_pick_the_network
```

The test uses unix sockets only, so it runs in the job `restricted-host`.

## Start condition

T-061 and T-096 are done.

# T-099: Router: `podnet forward` for each network, UDP forwards, a DNS door, and `podnet expose`

**Source:** `docs/research/podnet/capabilities.md`, sections 2.1 to 2.3;
`docs/research/podnet/mwan-field.md`, section 3 (F4b).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A port forward exists for WARP only (`warp forward`, `src/warp/forward.rs`). No forward carries
UDP. The DNS door works for WARP only. Each way in to a local service is its own command.

## Premise

- `warp forward -L` dials through WARP. `warp proxy --dns` answers DNS through WARP.
- `tunnel`, `relay node` and `net proxy --forward` each expose a local service.

## Approach

1. Add `podnet forward -L LISTEN=NET:HOST:PORT` for each network. Keep `warp forward` as an
   alias.
2. Add UDP forwards, and a DNS door for each network.
3. Add `podnet expose TARGET` with a choice of the tunnel, the relay or the switch, as an alias of
   the three commands.

## Prove

```sh
cargo test --workspace -- forward_over_a_network forward_udp_echo dns_door_over_a_network expose_via_relay_is_a_relay_node
```

## Start condition

T-059 and T-062 are done.

# T-100: Router: a config file, and `podnet route` with `--detach` and autostart

**Source:** `docs/research/podnet/capabilities.md`, section 2.3;
`docs/research/podnet/mwan-field.md`, section 2.2 (R3).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The parts of T-095 to T-099 have no command. A router with several networks, groups and doors is
too long for a command line.

## Premise

- `src/yaml.rs` reads YAML with no new crate.
- `src/detach.rs` and `src/autostart.rs` supervise a command and start it at boot.

## Approach

1. Add `podnet route [--config FILE]`, with the keys of the flags in the file.
2. Read the file with `src/yaml.rs`.
3. Make `--detach --name NAME` and `autostart add` work with it.

## Prove

```sh
cargo test --workspace -- route_config_errors_name_the_key
cargo test --test detach -- route_detaches_and_lists_its_members
```

## Start condition

T-097 and T-098 are done.

# T-101: Router: the live step with WARP, the relay and direct, and a failover

**Source:** `docs/research/podnet/capabilities.md`, section 2.5;
`docs/research/podnet/mwan-field.md`, section 4 (rank 13); the owner's ruling of 2026-11-05
(`docs/decisions.md`, Live WARP devices).
**Category:** measurement
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The loopback tests use fake upstreams. Only a live run proves the router with a real WARP session
and the real relay.

## Premise

- The live job drops UDP 7844 already, with iptables (`.github/workflows/live.yml`).
- `http://1.1.1.1/cdn-cgi/trace` shows `warp=on` through WARP.
- The WARP service limits new devices for each address: live run 41987488063 got HTTP 429
  (error 1015) at the nested session step. Each device that a step registers adds to this risk.

## Approach

1. Run `podnet route` with the networks `warp`, `relay` and `direct`, a door on TCP and a group.
   Register the second device in the step that needs it, and honour the `Retry-After` of a 429
   once before the step fails.
2. Check `warp=on` through `warp` and `warp=off` through `relay`.
3. Drop TCP 443 to the MASQUE front door with iptables. Check that the group fails over to the
   relay. Restore the rule.
4. Register a second WARP device for the group, and delete it at the end of the step.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Live WARP devices): a live test of the router
registers and deletes a WARP device in each run.

## Prove

```sh
gh workflow run live.yml
```

The step "router" passes.

## Start condition

T-100 is done.

# T-102: Copy the mailbox client, the code words and the SPAKE2 phases of podssh

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.2 and 3 (C8);
`docs/research/podnet/capabilities.md`, sections 4.2 to 4.4; the owner's rulings of 2026-11-05
(`docs/decisions.md`, File transfer and Crypto crates).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

podnet has no rendezvous: no short code and no PAKE. `share` gives a long URL, and Cloudflare
sees the plain bytes.

## Premise

- podssh has the client of the magic-wormhole mailbox over a WebSocket
  (`wss://relay.magic-wormhole.io/v1`, then `wss://mailbox.mw.leastauthority.com/v1`), SPAKE2
  (`spake2 0.4`), phases sealed with SecretBox (`crypto_secretbox`), and the PGP word list
  (`Azathothas/podssh:crates/podssh-relay/src/code/`, about 1,185 lines).
- Its run and exchange files are the pairing of podssh, not a file transfer.

## Approach

1. Copy `mailbox.rs`, `wormhole.rs`, `phrase.rs`, `words.rs` and the constants of `mod.rs` into a
   rendezvous module of `podnet-relay`.
2. Replace the WebSocket session of podssh with tokio-tungstenite over `egress::dial`, so that the
   proxy applies.
3. Set the AppID of the magic-wormhole file transfer (`lothar.com/wormhole/text-or-file-xfer`).
   Add a mailbox variable with its row in `src/manual/facts.rs`.
4. Copy the unit tests with the code.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, File transfer and Crypto crates): `podnet send` and
`podnet receive` speak magic-wormhole (mailbox, SPAKE2, transit), with the public mailbox and
transit servers as the default. `spake2` 0.4 and `crypto_secretbox` are accepted.

The owner, 2026-11-05 (`docs/decisions.md`, Shared crates): the shared crates of `PodUtils/podcrates` hold this code. podnet depends on the shared crate; it does not copy the code.

## Prove

```sh
cargo test -p podnet-relay -- rendezvous::
cargo deny check
```

A wrong code fails at both ends. A loopback test runs against a stand-in of the mailbox.

## Start condition

T-049 is done.

The shared crates exist in `PodUtils/podcrates` (T-137; the ruling "Order" of 2026-11-05 in `docs/decisions.md`).

# T-103: The file-transfer protocol and the transit protocol of magic-wormhole

**Source:** `docs/research/podnet/capabilities.md`, section 4.3;
`docs/research/podnet/podssh-copy.md`, sections 2.2 (the wire choice) and 3 (C9); the owner's
ruling of 2026-11-05 (`docs/decisions.md`, File transfer).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

podssh has the mailbox and SPAKE2 parts, but not the file-transfer protocol of magic-wormhole: the
offer, the answer, the transit hints, the transit handshake and the records. Without them,
`wormhole send` and `podnet receive` cannot talk.

## Premise

- podssh has a transit carrier (`Azathothas/podssh:crates/podssh-relay/src/transit/`, 1,013
  lines). Its hello and proof are its own words after the relay line of the transit relay.
- magic-wormhole sends a directory as a zip file. No crate of the lock reads deflate.
- A host with TCP 443 only through a proxy needs the transit relay on 443 (the WebSocket relay of
  Least Authority).

## Approach

1. Write the version phase and the offer and answer phases: a text, a file and a directory.
2. Write a directory as a zip with no compression. Read a deflated zip with an inflate decoder:
   choose between own code and a pure Rust crate, and write the choice with its `cargo deny`
   result in the Decision section.
3. Adapt the transit carrier of podssh to the transit protocol of magic-wormhole: the hints, the
   relay handshake, the sender and receiver handshakes, and the records sealed with SecretBox
   under the transit key.

## Prove

```sh
cargo test -p podnet-relay -- wormhole_transfer_
```

Each phase is checked against messages captured from the Python magic-wormhole. A changed record
fails.

## Start condition

T-102 is done.

# T-104: The podnet relay as a carrier of a transfer

**Source:** the owner's ruling of 2026-11-05 (`docs/decisions.md`, File transfer);
`docs/research/podnet/capabilities.md`, section 4.3 (road 1).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Two hosts that reach only TCP 443 through a proxy may not reach a transit relay. The owner named
the podnet relay as one more carrier.

## Premise

- T-087 resumes a relay session past the cap of 64 MiB.
- A client of magic-wormhole ignores a transit hint of a kind that it does not know.

## Approach

1. Add a transit hint of podnet's own kind. The sender pairs a relay node and sends the connect
   token inside a sealed phase.
2. The receiver connects through the relay. The layer resumes past the cap.

## Prove

```sh
cargo test -p podnet-relay -- transfer_over_the_relay_crosses_the_cap
```

## Start condition

T-087 and T-103 are done.

# T-105: `podnet send` and `podnet receive`

**Source:** `docs/research/podnet/capabilities.md`, sections 4.2, 4.5 and 4.7; the owner's ruling
of 2026-11-05 (`docs/decisions.md`, File transfer).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The parts of T-102 and T-103 have no command.

## Premise

- A code in argv is visible to other users in the process list.
- One wrong guess must end the code.

## Approach

1. Add `podnet send PATH...` with `--via`, `--mailbox URL`, `--words N` and `--text TEXT`. It
   prints the code.
2. Add `podnet receive` with `--out DIR`, `--yes` and `--via`. It reads the code from the prompt
   or from stdin, never from argv.
3. Check the SHA-256 of each file. Map each fault to an exit code of `src/exit.rs`.

## Prove

```sh
cargo test --test cli -- send_and_receive_on_the_loopback a_wrong_code_ends_the_code
```

## Start condition

T-103 is done.

# T-106: An interop test with the Python magic-wormhole, and the live step of a transfer of 100 MiB

**Source:** `docs/research/podnet/podssh-copy.md`, sections 2.2 and 3 (C15);
`docs/research/podnet/capabilities.md`, section 4.7.
**Category:** measurement
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Unit tests against captured messages do not prove that `wormhole send` and `podnet receive` talk.
Only a real public mailbox and the real relay prove the default path.

## Premise

- podssh runs magic-wormhole's Python library and mailbox server on the loopback
  (`Azathothas/podssh:scripts/wormhole-peer.py`,
  `Azathothas/podssh:.github/workflows/pair-code.yml`).

## Approach

1. Add a workflow: a venv with `magic-wormhole`, its mailbox server and its transit relay on the
   loopback. Run `wormhole send` to `podnet receive`, and `podnet send` to `wormhole receive`.
2. Add a live step: a random file of 100 MiB through the public mailbox and transit, and through
   the relay. Compare the SHA-256.

## Prove

```sh
gh workflow run wormhole-interop.yml
gh workflow run live.yml
```

## Start condition

T-104 and T-105 are done.
