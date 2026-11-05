This file holds the entries of milestone M5: the defects and the small gaps that the field report
of 0.3.0-beta.12 (`docs/reports/field-report-2026-11-05.md`), the lab kit, the section "Open
work" of `docs/maintenance.md` and the seccomp ideas of the vn kit found.
`docs/research/podnet/mwan-field.md`, section 4, ranks them. The lab kit's reports are
attachments, not files of the repository: `docs/research/podnet/mwan-field.md`, section 2.3,
quotes them. These entries can start at any time from M0. An entry that changes a file of a split
of M2 lands before that split starts, or after it ends. Names: before T-016 a variable is
`CFRS_X`; after it, `PODNET_X`. A fix in a module that podcrates already holds, or that
T-137 plans to move (`src/warp/`, `src/resolve.rs`, `src/egress.rs`, `src/cloudflare/`), lands in
podnet until podnet takes the crate. Tell the podcrates session of the fix (`docs/decisions.md`, Who edits a
shared crate). After the take, the fix goes to PodUtils/podcrates.

# T-063: seccomp: a TCP socket stays tracked after its connect, and its options and addresses come from its entry

**Source:** `docs/reports/field-report-2026-11-05.md`, item 2;
`docs/research/podnet/mwan-field.md`, section 3 (F2, W-F2, rank 1);
`docs/research/podnet/vn.md`, section 3.1 (P3, part a).
**Category:** defect
**Milestone:** M5
**Priority:** P1
**Effort:** M
**Status:** open

## Problem

Under the seccomp backend, the default of `warp exec`, `radicle-node` logs
`TCP_NODELAY: Not supported (os error 95)`. Then each peer resets the connection during the
handshake. With `--backend netns`, the same program works. The reporter lost about one hour.

## Premise

- Read: after a TCP connect succeeds, `handle_connect` removes the descriptor from the table of
  the supervisor (`crates/podnet-netns/src/seccomp.rs`). Then `setsockopt` goes to the kernel
  AF_UNIX socket and gives EOPNOTSUPP for `TCP_NODELAY` and `TCP_KEEPIDLE`. `getsockname` and
  `getpeername` go to the kernel and give the AF_UNIX address.
- The evidence log shows `ss_family: 1` for the local and the peer address
  (`docs/reports/field-report-2026-11-05-evidence.log`).
- Read: `getpeername` of a tracked stream gives the local bound address, not the peer.
- The only test of the addresses uses a UDP socket (`tests/pod_seccomp.rs`).
  `crates/podnet-netns/README.md` says that each socket shows its logical address.
- Not proven: that the AF_UNIX addresses, not the options, cause the resets. A run of
  radicle-node decides it.

## Approach

1. Keep an entry for a connected TCP socket: its state, its peer (the address, or the fake
   address of a name), a plausible local address, and each option that the program set.
2. Answer `getpeername` with the peer and `getsockname` with the local address. Answer
   `setsockopt` of the IP and TCP levels with 0, and `getsockopt` with the value that the program
   set.
3. Make `getpeername` of a tracked stream give its peer.
4. Change `crates/podnet-netns/README.md` and the words of `pod doctor` about these calls.

## Prove

```sh
cargo test --test pod_seccomp -- seccomp_tcp_socket_keeps_its_options_and_addresses
```

The new C test connects through the SOCKS5 stand-in of the test. It asserts that
`setsockopt(TCP_NODELAY)` gives 0, `getsockopt(TCP_NODELAY)` gives 1, `getpeername` gives the
AF_INET target and port, and `getsockname` gives an AF_INET address. Plant: remove the entry
after the connect again. The test must fail. Then run radicle-node once under `warp exec`, and
write the result in the Done section.

# T-064: seccomp: one entry for each socket of each process, and copies of a descriptor are tracked

**Source:** `docs/research/podnet/mwan-field.md`, section 3 (F2, W-F2);
`docs/research/podnet/vn.md`, section 3.1 (P3, part b).
**Category:** defect
**Milestone:** M5
**Priority:** P1
**Effort:** M
**Status:** open

## Problem

The table of the supervisor uses the descriptor number as its key, and each process of the pod
shares it. A `close` of descriptor N in one process drops the entry of N for each process. A copy
made by `dup`, `dup2` or `fcntl(F_DUPFD)` has no entry, so it sends to the wrong place.

## Premise

- Read: the descriptor table and the `close` branch in `crates/podnet-netns/src/seccomp.rs`.
- `docs/research/podnet/vn.md`, section 3.1: the C supervisor of vn counts references and misses
  `F_DUPFD`. The Rust `try_clone` uses `F_DUPFD_CLOEXEC`.

## Approach

1. Use the pair (thread group id, descriptor) as the key. Copy the entries of the parent at a
   fork.
2. Intercept `dup`, `dup2`, `dup3`, and `fcntl` with `F_DUPFD` and `F_DUPFD_CLOEXEC`. Copy the
   entry to the new descriptor.
3. Compare this with a key of the socket inode (from `/proc/PID/fd/N`). Write the choice and the
   reason in the Decision section.

## Prove

```sh
cargo test --test pod_seccomp -- seccomp_close_in_a_child_keeps_the_parent_entry seccomp_dup_keeps_the_udp_destination
```

## Start condition

T-063 is done.

# T-065: seccomp: hand a plain upstream descriptor to the program after its handshake

**Source:** `docs/research/podnet/vn.md`, sections 3.1 (P3, part c) and 5 (question 2).
**Category:** feature
**Milestone:** M5
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

For a plain upstream (a Unix socket, or TCP to an HTTP or SOCKS5 proxy, with no TLS and no
framing in the process), the supervisor relays each byte after the handshake. The program holds
an AF_UNIX socket pair, not the upstream socket.

## Premise

- The kernel can install a descriptor at a number of the target process
  (`SECCOMP_IOCTL_NOTIF_ADDFD` with `SECCOMP_ADDFD_FLAG_SETFD`). The seccomp backend uses ADDFD
  already (`crates/podnet-netns/src/seccomp.rs`).
- After a handoff, the supervisor sees no byte of that flow: no byte count, no idle limit, no
  log line of the flow.

## Approach

1. After the handshake with a Unix-socket upstream, install the upstream descriptor at the
   program's descriptor number. Drop the relay task.
2. Keep the relay for TCP upstreams. Ask the owner before the handoff becomes the default for
   them, because of the lost byte counts.

## Prove

```sh
cargo test --test pod_seccomp -- seccomp_handoff_of_a_unix_upstream_leaves_no_relay
```

The test asserts that `setsockopt(TCP_NODELAY)` on the handed descriptor gives 0 from the kernel,
and that no relay task stays.

## Start condition

T-064 is done.

# T-066: seccomp: ICMP datagram sockets, `recvmmsg`, and UDP names over 255 bytes

**Source:** `docs/research/podnet/vn.md`, section 3.1 (P4); `docs/maintenance.md`, section "Open
work" (the bullet of the pod seccomp backend).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

Three calls get a wrong result under the seccomp backend:

1. `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` is relayed as UDP.
2. A `recvmmsg` read gets the AF_UNIX source address, not the real one.
3. A UDP target name over 255 bytes is cut.

## Premise

- Read: `handle_socket` does not read the protocol argument (`crates/podnet-netns/src/seccomp.rs`).
- `recvmmsg` is not in the list of intercepted calls. The ruling of 2026-11-04 names `recvfrom`
  and `recvmsg` (`docs/decisions.md`, pod seccomp UDP).
- `wrap_udp_name` cuts a name over 255 bytes (`crates/podnet-netns/src/seccomp.rs`).

## Approach

1. Give ICMP datagram sockets their own kind. The supervisor answers an echo to the gateway of
   the pod. Another destination gets `EACCES`.
2. Intercept `recvmmsg` as a series of `recvmsg` reads, and write the real source of each
   message.
3. Refuse a UDP name over 255 bytes with `EINVAL` and one log line.

## Decision

The owner, 2026-11-04 (`docs/decisions.md`, pod seccomp UDP, #285): the seccomp backend
intercepts `recvfrom` and `recvmsg` on its sockets, so that a UDP reader sees the real source
address. `recvmmsg` is the same need.

## Prove

```sh
cargo test --test pod_seccomp -- seccomp_icmp_echo_to_the_gateway seccomp_recvmmsg_gets_the_real_source seccomp_long_udp_name_is_refused
```

The ICMP test follows the ICMP part of the vn kit's static guest: an echo to the gateway gets an
answer; an echo to 192.0.2.1 gets `EACCES`.

# T-067: seccomp: a slow `connect` dial does not stop the supervisor for the other calls

**Source:** `docs/maintenance.md`, section "Open work" (the bullet of the pod seccomp backend).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A blocking `connect` dial in the supervisor stops each other call of the program until the dial
ends. A program with a slow upstream freezes in calls that need no network.

## Premise

- Read: the notification loop dials the upstream before it answers the next notification
  (`supervise_seccomp` and `handle_connect` in `crates/podnet-netns/src/seccomp.rs`).
- A notification id stays valid until the supervisor answers it. `SECCOMP_IOCTL_NOTIF_ID_VALID`
  tells whether the task still waits.

## Approach

1. Run each upstream dial in its own task. Answer its notification when the dial ends.
2. Serve the other notifications while the dial runs.
3. Check the id before the answer. Drop the dial when the task is gone.

## Prove

```sh
cargo test --test pod_seccomp -- seccomp_a_slow_dial_does_not_stop_other_calls
```

An upstream stand-in answers after 2 s. A second thread of the program calls `getsockname`, and
it returns in less than 100 ms.

# T-068: WARP: a probe of the TCP data path renews a session that carries no TCP

**Source:** the lab kit's report masque-session-tcp-blackhole.md, in
`docs/research/podnet/mwan-field.md`, section 2.3 (B1, rank 2).
**Category:** defect
**Milestone:** M5
**Priority:** P1
**Effort:** M
**Status:** open

## Problem

A MASQUE session can carry ICMP and UDP but no TCP. podnet keeps it as alive, and each TCP flow
fails until a restart. The edge causes the state; a new session ends it.

## Premise

- Read: the liveness check of HTTP/2 sends a PING only when no data came, and calls the session
  dead after three intervals with no pong and no data (`MAX_MISSED_PONGS` in
  `src/warp/session.rs`). ICMP and UDP replies count as data.
- The `Live` watcher can renew a session before the old one closes (`renew_due` in
  `src/warp/live.rs`).
- The report shows that the same host and binary work with another device at the same time.

## Approach

1. Run one probe task for each live WARP stack. Each 30 s with no TCP connect that succeeded,
   connect to 1.1.1.1:443 through the stack, with a limit of 5 s.
2. After three misses, mark the session `tcp-dead` and renew it through the path of
   `renew_due`. The old flows drain. Log `reason=tcp-probe`.
3. Add `--probe HOST:PORT` and `--probe off`.
4. Show `data_path` (`ok` or `tcp-dead`) and the last probe time in `status`, the ready document
   and `warp status`.

## Prove

```sh
cargo test --workspace -- warp_probe_renews_a_session_with_no_tcp
```

The test uses the "silenced" edge of T-012, or a fake session that drops each TCP SYN. The probe
renews the session after three misses.

# T-069: `warp tun`: a SYN probe of the session, and `--session-max-age`

**Source:** the lab kit's report masque-session-tcp-blackhole.md, in
`docs/research/podnet/mwan-field.md`, section 2.3 (B1, fixes 2 and 3).
**Category:** defect
**Milestone:** M5
**Priority:** P1
**Effort:** L
**Status:** open

## Problem

`warp tun` reconnects only when its run loop returns. It has no probe of the data path, so the
state of T-068 stays for ever. `--session-max-age` is refused for `warp tun`.

## Premise

- Read: the keep loop of `warp tun` opens a new session only when `tun::run` returns
  (`src/warp/tun.rs`, `src/main.rs`).
- Read: `src/main.rs` refuses `--session-max-age` with `warp tun`.
- The TUN carries the packets of the host, so the probe of T-068 cannot open a stack socket here.

## Approach

1. Put a TCP SYN from the tunnel address and a reserved port to the probe target into the
   session.
2. Take the SYN-ACK or the RST out of the inbound path before the TUN (match the reserved port).
   Answer with a RST.
3. After three misses, return an error from `tun::run`. The keep loop opens a new session.
4. Allow `--session-max-age` on `warp tun`: a timer around `tun::run`.

## Prove

```sh
cargo test --workspace -- warp_tun_probe_takes_its_answer_out warp_tun_probe_ends_a_dead_session
cargo test --test cli -- warp_tun_takes_session_max_age
```

The first test asserts that a SYN-ACK to the probe port is not written to the TUN.

## Start condition

T-068 is done.

# T-070: `warp exec`, `warp shell` and `warp nc` find a running `warp up` with another state directory

**Source:** `docs/reports/field-report-2026-11-05.md`, items 3, 5 and 6;
`docs/research/podnet/mwan-field.md`, section 3 (F3, F5, F6, W-F3, rank 3).
**Category:** defect
**Milestone:** M5
**Priority:** P1
**Effort:** S
**Status:** open

## Problem

`warp exec` failed with "warp up is not running (no answer on /state/kage/cfrs/run/warp.sock)".
The reporter had started `warp up` with another state directory. `warp exec` found the socket
only with both the state directory variable and the WARP socket variable set.

## Premise

- Read: `exec_in_pod`, `shell`, the `nc` path and the agent use `socket_path()`, which is the
  run directory and `warp.sock` (`src/warp/up.rs`, `src/warp/nc.rs`, `src/agent.rs`).
- Read: `run_dir()` depends on the state directory (`src/instances.rs`).
- Read: `warp up` writes `PODNET_WARP_SOCKET` to `warp.env` and to the program of the pod, but
  nothing reads it (`src/warp/up.rs`).
- `warp.env` is in the same directory, so to read the env file alone does not help.

## Approach

1. Read the WARP socket variable first.
2. Add `--socket PATH` to `warp exec`, `warp shell` and `warp nc`.
3. Make `warp up` write a pointer file at a fixed place of the user (the runtime directory, else
   a directory of the user in the temporary directory). It has mode 0600 and an owner check. It
   holds the socket and the state directory.
4. Make the error list each path tried, and name the state directory of a running `warp up` when
   it finds one.
5. Add the variable to `src/manual/facts.rs`. In the manual, name the state directory variable
   for a host whose default state directory is on a shared disk.

## Prove

```sh
cargo test --workspace -- warp_exec_finds_warp_up_of_another_state_directory the_lookup_order_of_the_warp_socket
```

The first test starts `warp up` with a state directory A (with the stand-in of T-012), then runs
`warp exec -- true` with no state directory variable. It exits 0.

# T-071: `warp exec` and `warp shell` take `--backend`, name the backend in one line, and log the seccomp emulation

**Source:** `docs/reports/field-report-2026-11-05.md`, items 2 and 8 (request 2);
`docs/research/podnet/mwan-field.md`, section 3 (F2b, W-F2b, rank 4); the owner's ruling of
2026-11-05 (`docs/decisions.md`, Pod backend).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

`warp exec` gave the reporter the seccomp backend with no word about its limits. `doctor` names
them, but nobody reads it before a failure. A reset from inside the pod looks like a refusal of
the peer.

## Premise

- Read: `warp exec` always passes `--prefer-udp` (`src/warp/up.rs`), so `auto` takes seccomp
  first where netns works (`crates/podnet-netns/src/lib.rs`).
- `warp exec` and `warp shell` have no `--backend`.
- The words about the seccomp limits are in `crates/podnet-netns/src/doctor.rs`.

## Approach

1. Add `--backend auto|netns|seccomp` to `warp exec` and `warp shell`. Pass it to the pod.
2. Print one line on stderr that names the backend and its limits, for example "seccomp: socket
   options and addresses are emulated; use --backend netns". `-q` and the quiet variable remove
   it.
3. With `-v`, log each emulation of the seccomp layer at the info level ("socket emulated as a
   socket pair", "setsockopt answered").
4. Keep the order of `auto` until T-113.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Pod backend): `warp exec` and `warp shell` get
`--backend` and a line that names the backend.

## Prove

```sh
cargo test --workspace -- warp_exec_names_its_backend_once warp_exec_passes_the_backend_to_the_pod seccomp_logs_its_emulation_at_info
```

# T-072: `warp tun` sets `rp_filter` to 0 on its interface

**Source:** the lab kit's report warp-tun-rp-filter-strict.md, in
`docs/research/podnet/mwan-field.md`, section 2.3 (B2, rank 5).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

On a host with systemd, each new TUN of `warp tun` gets `rp_filter` 2. When the only egress is a
loopback proxy and the WAN routes are in their own tables, the loose mode drops the replies.

## Premise

- podnet never writes `rp_filter`. `Tun::create` sets only the interface, the address, the mask,
  the MTU and the flags (`src/warp/tun.rs`).
- The likely source: systemd-udevd runs systemd-sysctl for each new interface, and its default
  file sets `rp_filter = 2`. Not measured here.
- The value that the kernel uses is the larger of `conf.all` and `conf.IF`.

## Approach

1. After `Tun::create`, write 0 to the `rp_filter` file of the interface under
   `/proc/sys/net/ipv4/conf/`.
2. Read it again after 2 s and at each new session, because udev can run after podnet.
3. Warn when the value that the kernel uses is not 0 (for example, `conf.all` is 1).
4. Add `--keep-rp-filter` to keep the value. Show the value in the ready document and in
   `doctor`.

## Prove

```sh
cargo test --workspace -- the_effective_rp_filter_is_the_larger_value
gh workflow run live.yml
```

The live step of `warp tun` reads 0 for the interface.

# T-073: `warp forward`: the pins of `--resolve`, and the list of forwards

**Source:** `docs/reports/field-report-2026-11-05.md`, items 4 and 8 (requests 4 and 5);
`docs/research/podnet/mwan-field.md`, section 3 (F4a, F4b, W-F4a, W-F4b, ranks 6 and 7).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

1. `--resolve` parses on `warp forward` and does nothing. A user cannot pin the address of a host
   with unreliable DNS.
2. The text of `ps` shows the first listen address of a forward only, and no target. The reporter
   kept notes of each mapping.

## Premise

- Read: `warp forward` resolves each name through the tunnel (`resolve_all` in
  `src/warp/proxy.rs`). The pins are read only in the host chain (`resolve_chain` in
  `src/resolve.rs`).
- Read: the ready document has `forward: [{listen, to}]`, so `ps --json` shows each forward
  (`src/main.rs`). The text rows print `forward` only when it is a string.

## Approach

1. Add a public function in `src/resolve.rs` that gives the pin of a name. Make `resolve_all` and
   `resolve` of `src/warp/proxy.rs` return the pin before any query. Then `--resolve` works for
   `forward`, `proxy`, `nc` and `exec`.
2. For an array `forward`, make `ps` print each `LISTEN -> TO`.
3. Add `warp forward --list`: the forwards of `ps`.

## Prove

```sh
cargo test --workspace -- warp_resolve_takes_the_pin_first ps_prints_each_forward
```

The first test asserts that a pinned name gives the pin and sends no DNS packet into the stack.

## Correction

2026-11-05, `src/resolve.rs` moves to `pod-dns` (T-137). Until podnet takes `pod-dns`, this fix of `src/resolve.rs`
lands in podnet and the podcrates session ports it. After the take, the fix goes to PodUtils/podcrates.

# T-074: `warp export`: the reserved bytes in the file, `--check`, and a TCP probe on the WireGuard leg

**Source:** the lab kit's report warp-export-kernel-wg-data-path-degrades.md, in
`docs/research/podnet/mwan-field.md`, section 2.3 (B3, rank 9).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** L
**Status:** open

## Problem

An exported device in kernel WireGuard has fresh handshakes and a data path in one direction
only. The user cannot tell a device that needs the reserved bytes from a dead device. The
WireGuard leg of podnet checks only the handshakes, so it does not see the same state.

## Premise

- Read: `warp export` writes the reserved bytes only as a comment (`Reserved` in
  `src/warp/export.rs`), and as `reserved` in the JSON form. Kernel WireGuard and wg-quick send
  zeros there.
- Read: the WireGuard leg sends the `client_id` bytes of the device in bytes 1 to 3 of each
  message (`src/warp/wg.rs`).
- Read: `WgKeepalive` checks only the handshakes (`src/warp/wg.rs`).

## Approach

1. Write in the head of the export and in the manual: what the reserved bytes are, that kernel
   WireGuard and wg-quick send zeros, and that `warp tun --leg wireguard` sends them.
2. Add `warp export --check`: run the WireGuard leg with the exported device, once with the
   reserved bytes and once with zeros, with a TCP probe through each. Print "device ok", "needs
   reserved bytes" or "device data path dead, use --new".
3. Add the TCP probe of T-068 to `WgKeepalive` for `--leg wireguard`.

## Prove

```sh
cargo test --workspace -- a_seal_with_zero_reserved_differs_in_three_bytes wireguard_probe_renews_a_dead_leg
gh workflow run live.yml
```

A live step runs `warp export --check` on the device of the run.

## Start condition

T-068 is done.

# T-075: The datagram socket of the vnet shim takes the same user only

**Source:** `docs/maintenance.md`, section "Open work" (the bullet of the vnet shim UDP);
`docs/virtual-network.md`.
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The datagram socket of the shim takes datagrams from any user. The stream sockets of the shim and
the sockets of the switch take the same user only.

## Premise

- `docs/virtual-network.md` says that the datagram socket of the shim has no check of the user.
- The switch drops a datagram of another user with `SO_PASSCRED` (`src/vnet/switch.rs`).

## Approach

1. Set `SO_PASSCRED` on the datagram socket of the shim.
2. Read the credentials of each datagram. Drop a datagram of another user, with one log line.
3. Change `docs/virtual-network.md`.

## Decision

The owner, 2026-11-04 (`docs/decisions.md`, vnet sockets, #288 and #289): the unix sockets of
the shim and the switch take the same user only.

## Prove

```sh
cargo test --workspace -- shim_datagram_of_another_user_is_dropped
```

The test runs as root and sends from a child with another uid. It is skipped, with one line, when
it does not run as root.

# T-076: A CI job runs the tests with the loopback down

**Source:** `docs/maintenance.md`, section "Open work" (#217).
**Category:** chore
**Milestone:** M5
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

No CI job runs the tests with the loopback down. A new test that binds 127.0.0.1 with no
`need_loopback!()` fails on such a host, and CI does not see it.

## Premise

- `unshare -n` needs user namespaces, which the ubuntu-24.04 runner restricts.
- `docs/development.md` has the local command.
- The job `restricted-host` refuses `bind(AF_INET)` (`scripts/restricted-host.sh`).

## Approach

1. Add a job to `.github/workflows/ci.yml` that makes the network namespace as root and runs the
   tests as the runner user:
   `sudo unshare -n -- setpriv --reuid=$(id -u) --regid=$(id -g) --init-groups cargo test --workspace`,
   with `HOME` and `PATH` kept.
2. When `setpriv` cannot keep the environment, lower the AppArmor restriction for the job
   (`kernel.apparmor_restrict_unprivileged_userns=0`) and use `unshare -rn`.

## Prove

```sh
gh workflow run ci.yml
```

The new job passes. Plant: remove `need_loopback!()` from one test. The job must fail.

# T-077: An ingress `path:` rule matches the decoded path, as cloudflared does

**Source:** `docs/maintenance.md`, section "Open work" (`path:`, #289).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

An ingress `path:` rule matches the path as it came, with its `%XX` escapes. cloudflared matches
the decoded path. A rule of a cloudflared configuration then matches other requests here.

## Premise

- `src/ingress.rs` matches the rule with the `regex` crate.
- The owner, 2026-11-04 (`docs/decisions.md`, `path:`, #269 item 3): a `path:` is a regular
  expression, as in cloudflared. The match has no anchor, as in cloudflared.
- Go gives the decoded path in `URL.Path`. Not read in the source of cloudflared here.

## Approach

1. Read the matcher of cloudflared to confirm the decoded path. Write the result in the
   Correction section when it differs.
2. Decode `%XX` of the path before the match.
3. Keep the match with no anchor. Write both facts in the manual and in `README.md`.

## Prove

```sh
cargo test --workspace -- a_path_rule_matches_the_decoded_path
```

The test asserts that `/a%20b` matches the rule `^/a b$`.

# T-078: `pod doctor` uses the verdict words of `doctor` and has a `schema` key

**Source:** `docs/maintenance.md`, section "Open work" (`podnet pod doctor`); the owner's ruling of
2026-11-04 (`docs/decisions.md`, Doctor).
**Category:** defect
**Milestone:** M5
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

`pod doctor` keeps its own words (`ok`, `no`, `available`) and has no `schema` key. The other
doctors and `status` use one vocabulary and a schema.

## Premise

- `crates/podnet-netns/src/doctor.rs` writes the words of the pod.
- `src/doctor.rs` and `src/report.rs` write the vocabulary of the other doctors.

## Approach

1. Map each probe of the pod to the verdict words of `doctor`.
2. Add the key `schema` and the version to the JSON form.
3. Keep exit 3 when no backend can run.
4. Write the change of the JSON words in the `## Breaking` list of the next release note.

## Decision

The owner, 2026-11-04 (`docs/decisions.md`, Doctor): one verdict vocabulary for each check.

## Prove

```sh
cargo test --test cli -- pod_doctor_json_has_the_schema_and_the_verdicts
```

# T-079: Read the numbers of #206 and #184 in a live run

**Source:** `docs/maintenance.md`, section "Open work" (#206 and #184).
**Category:** measurement
**Milestone:** M5
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

Two reports wait for numbers. #206: small requests through `connect` can be slower than through
the URL. #184: `warp exit` can miss the IPv6 egress address.

## Premise

- `scripts/live-throughput.sh` prints the median time of small requests over the URL and over
  `connect`.
- `scripts/live-batch2.sh` prints whether `warp exit` found the IPv6 address. When the trace
  gives no IPv6 address, the fallback is the TXT record of `whoami.cloudflare`.

## Approach

1. Read both lines in the next run of `live.yml`.
2. When the median through `connect` is more than 1.5 times the median through the URL, write a
   defect entry with the numbers.
3. When `warp exit` finds no IPv6 address but the trace has one, write a defect entry.
4. Else write the numbers in the Done section.

## Prove

```sh
gh workflow run live.yml
gh run view RUN --log | grep -e median -e ipv6
```

# T-080: The errors of a config file name the line

**Source:** `docs/maintenance.md`, section "Open work" (#172 item 3).
**Category:** feature
**Milestone:** M5
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

An error of a config file names the rule and the key, not the line. In a long file the user
must search for the place.

## Premise

- `src/yaml.rs` keeps no positions.
- `src/config.rs` writes the errors with the rule and the key.

## Approach

1. Keep the line and the column of each node in `src/yaml.rs`.
2. Add the line to each error of `src/config.rs`, beside the rule and the key.

## Prove

```sh
cargo test --workspace -- a_config_error_names_its_line
cargo check --manifest-path fuzz/Cargo.toml --bins
```

The fuzz target `config_yaml` still builds.

# T-081: The tailnet front door warns when `tailscaled` is not logged in

**Source:** `docs/maintenance.md`, section "Open work" (#181 item 6);
`docs/research/podnet/podssh.md`, section 2.3, step 1.
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The tailnet front door dials through a `tailscaled` that is not logged in. Each dial fails after
its limit of 10 s, and the user gets no hint.

## Premise

- `crates/podnet-netns/src/tailscale.rs` has the dial limit (`DIAL_TIMEOUT`) and a log line.
- The LocalAPI of `tailscaled` gives `BackendState` at `/localapi/v0/status`.

## Approach

1. At start, and after a failed dial, read `/localapi/v0/status`.
2. When `BackendState` is not `Running`, warn once with the state and the hint `tailscale up`.
3. Show the state in the doctor of the door.

## Prove

```sh
cargo test --workspace -- tailscale_front_door_warns_when_logged_out
```

A fake LocalAPI on a unix socket answers `NeedsLogin`. The headscale harness of T-114 runs the
same check against a real `tailscaled`.

# T-135: `podnet pod` prints its own program name in each message and in `--version`

**Source:** the rename trial of 2026-11-05 (`docs/research/podnet/rename.md`); the ruling
"podnet-netns" of 2026-11-05 in `docs/decisions.md`.
**Category:** defect
**Milestone:** M5
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The `podnet-netns` binary is dropped; `podnet pod` is the only CLI of the pod backends. The library
still writes its fixed prefix in each message, and `--version` prints the version line of the
library, not of the CLI. A user then sees a program name that does not exist.

## Premise

- `src/main.rs` calls `set_program_name` and `main_with_args` of the pod library.
- The library writes the prefix of its messages from a fixed text, not from the program name.

## Approach

1. Write each message prefix of the pod library from the program name that `set_program_name`
   gives.
2. Make `podnet pod --version` print the version line of the CLI.
3. Change the expected texts of the pod tests.

## Prove

```sh
cargo test --workspace pod
```

A test asserts that `podnet pod --version` starts with the name of the CLI and that an error of
`podnet pod` starts with `podnet pod:`.

## Start condition

T-019 and T-020 are done.
