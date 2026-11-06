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
**Status:** done

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

## Done

2026-11-06, commit 7614ddb (`T-063: seccomp: a TCP socket keeps its entry after its connect`). A
connected TCP socket is the entry `Sock::Connected` (`crates/podnet-netns/src/sockopt.rs`) until
the program closes it: its peer, a local address and its options. `setsockopt` keeps the value;
`getsockopt` gives it. `getpeername` of a stream with no connect gives `ENOTCONN`. A second
`connect` gives `EISCONN`, a `bind` after the connect `EINVAL`. The test is in a new file,
`tests/pod_seccomp_tcp.rs` (`tests/pod_seccomp.rs` is in the size allowlist): it passes. Plant: no
entry after the connect; the test fails with the values of the field report (`setsockopt` -1,
`ss_family` 1). The words of `pod doctor` about these calls stay true (they name the case with no
write to the memory of the program). The run of radicle-node under `warp exec` is not done: this
host has no radicle-node and no WARP. `seccomp.rs`: 1,900 to 1,803 lines.

# T-064: seccomp: one entry for each socket of each process, and copies of a descriptor are tracked

**Source:** `docs/research/podnet/mwan-field.md`, section 3 (F2, W-F2);
`docs/research/podnet/vn.md`, section 3.1 (P3, part b).
**Category:** defect
**Milestone:** M5
**Priority:** P1
**Effort:** M
**Status:** done

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

## Decision

The key is the socket inode of the program end (design b), not the pair (thread group id,
descriptor) (design a). The reasons:

- A `fork`, each `dup`, `dup2`, `dup3`, `fcntl(F_DUPFD)`, `fcntl(F_DUPFD_CLOEXEC)` and a
  descriptor sent with `SCM_RIGHTS` give the same socket, thus the same key. The filter stops no
  new system call (`intercepted_syscalls` does not change).
- Design a must copy the entries at each fork. The supervisor gets no notification at the
  return of `fork` or `clone`, so it does not know the pid of the child. An entry holds a
  socketpair and relay tasks, so a copy must be a shared reference with a count. A copy by
  `SCM_RIGHTS` stays without an entry.
- A thread shares the descriptor table of its process: `/proc/TID/fd/N` gives the same link as
  `/proc/TGID/fd/N`. No thread group id is necessary for the lookup.

The costs and the limits:

- Each stopped call on a descriptor does one `readlink` of `/proc/PID/fd/N`
  (`crates/podnet-netns/src/fdtable.rs`). The supervisor reads `/proc/PID/mem` for each call
  already, and that access needs more permission than the `readlink`.
- A `close` of a socket of the table reads the descriptor table of the caller first, then the
  tables of the other processes of the pod (the descendants of the first process, and each
  process that made a stopped call). It removes the entry only when no other descriptor refers
  to the socket.
- A descriptor that closes with no `close` call (the exit of a process, `execve` with
  close-on-exec, `close_range`) keeps its entry until a sweep. The sweep reads the descriptor
  tables of the pod and removes each entry of a socket that no process holds. It runs when the
  table doubles (from 64 entries), and before the table refuses a socket at `MAX_TRACKED_FDS`.
  Thus the table does not grow for the life of the pod. Until the sweep, the UDP association of
  such a socket stays open.
- `listen` puts a new socket at the number of the program (`SECCOMP_ADDFD` with
  `SECCOMP_ADDFD_FLAG_SETFD`). The entry moves to the key of the new socket. A copy of the
  descriptor made before the `listen` keeps the old socket and has no entry.
- An orphan process that made no stopped call is not in the list of the pod. A sweep or a
  `close` does not see its descriptors.

## Prove

```sh
cargo test --test pod_seccomp_fds -- seccomp_close_in_a_child_keeps_the_parent_entry seccomp_dup_keeps_the_udp_destination seccomp_closed_sockets_free_their_entries
```

## Start condition

T-063 is done.

## Done

2026-11-06, commit 7c3d1d8 (`T-064: seccomp: key the socket table by the socket inode`). The key
of the table is the inode of the socket of the program end (`crates/podnet-netns/src/fdtable.rs`).
The tests are in a new file, `tests/pod_seccomp_fds.rs` (`tests/pod_seccomp.rs` is in the size
allowlist). `seccomp_close_in_a_child_keeps_the_parent_entry`: the parent connects through the
proxy after a child closes its copy; it passes. `seccomp_dup_keeps_the_udp_destination`: a copy by
`dup`, `dup2`, `dup3`, `F_DUPFD` and `F_DUPFD_CLOEXEC` keeps the destination of a connected UDP
socket after the close of the first descriptor; it passes for each. Control on the old code: the
first test fails (`connect: Invalid argument`), the second fails (`send failed` for each copy).
`seccomp_closed_sockets_free_their_entries`: 5000 sockets closed with `close_range`; it passes.
Control with no sweep: it fails at socket 4096 (`EMFILE`).

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
**Status:** done

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

## Correction

2026-11-06. The three tests are in a new file, `tests/pod_seccomp_dgram.rs`: `tests/pod_seccomp.rs`
is in the size allowlist with no free lines. Run them with
`cargo test --test pod_seccomp_dgram`. The seccomp pod has no address of its own; its gateway is
`10.66.255.254`, the gateway of the netns backend (`TUN_GW`). An IPv6 ICMP socket gets its own
kind too, but each echo gets `EACCES`: the pod has no IPv6 gateway. `recvmmsg` waits for the first
message only (as with `MSG_WAITFORONE`); a blocking call of the kernel with no `MSG_WAITFORONE`
waits for `vlen` messages.

## Done

2026-11-06, commit f50da2e (`T-066: seccomp: ICMP datagram sockets, recvmmsg, and UDP names over
255 bytes`). An ICMP datagram socket is the entry `Sock::Icmp` (`crates/podnet-netns/src/icmp.rs`):
an echo to `10.66.255.254` gets an echo reply from that address, another destination gets
`EACCES`. The filter stops `recvmmsg`; the supervisor writes the real source and `msg_len` of each
message (`crates/podnet-netns/src/recvmmsg.rs`). A UDP name over 255 bytes gets `EINVAL` and one
log line (`crates/podnet-netns/src/dgram.rs`). `cargo test --test pod_seccomp_dgram`: 3 passed
(`seccomp_icmp_echo_to_the_gateway`, `seccomp_recvmmsg_gets_the_real_source`,
`seccomp_long_udp_name_is_refused`). Control on the code before the fix: 0 passed, 3 failed (no
echo answer; source family 0 and `msg_namelen` 0; the long name was sent).
`sh scripts/agent/check.sh`: exit 0.

# T-067: seccomp: a slow `connect` dial does not stop the supervisor for the other calls

**Source:** `docs/maintenance.md`, section "Open work" (the bullet of the pod seccomp backend).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** done

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

## Correction

- 2026-11-06: `tests/pod_seccomp.rs` is at its size limit (`scripts/size-allow.txt`). The test is in
  `tests/pod_seccomp_slow_dial.rs`. The command is
  `cargo test --test pod_seccomp_slow_dial -- seccomp_a_slow_dial_does_not_stop_other_calls`.
- 2026-11-06: the code has no non-blocking connect (`EINPROGRESS`). A `connect` of a socket with
  `O_NONBLOCK` also waits for the dial, before and after this change. The socket of the program is
  one end of an `AF_UNIX` socket pair, which is writable before the dial ends; thus `EINPROGRESS`
  and a later `SO_ERROR` cannot tell the program the result of the dial.

## Done

2026-11-06, commit 39ab845 (`T-067: seccomp: a slow connect dial does not stop the supervisor`).
The dial of a TCP `connect` runs in its own task (`crates/podnet-netns/src/connect.rs`). The
notification loop serves the other calls during the dial. At the end of the dial, the loop changes
the entry of the socket and answers each waiting call that `SECCOMP_IOCTL_NOTIF_ID_VALID` finds
pending; it drops the connection when no call waits. A second `connect` of the socket during the
dial waits for the same dial; a `close` during the dial gives `ECONNABORTED`.
`cargo test --test pod_seccomp_slow_dial`: 2 passed (`getsockname` during a 2 s dial returns in
less than 100 ms). Control on the code before the fix: 2 failed (`getsockname` took 1701 ms; the
`connect` gave 0 after the `close`). `sh scripts/agent/check.sh`: exit 0.

# T-068: WARP: a probe of the TCP data path renews a session that carries no TCP

**Source:** the lab kit's report masque-session-tcp-blackhole.md, in
`docs/research/podnet/mwan-field.md`, section 2.3 (B1, rank 2).
**Category:** defect
**Milestone:** M5
**Priority:** P1
**Effort:** M
**Status:** done

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

## Done

2026-11-06, commit 86050ee (`T-068: WARP: a TCP probe of the data path renews a session that
carries no TCP`). Steps 1 to 3: `Live::probed` in `src/warp/live.rs` (each 30 s, 5 s limit, 3
misses; then the path of `renew_due`, the log names `reason=tcp-probe`); `--probe IP:PORT` and
`--probe off` (a name is refused: the probe needs no DNS); `warp up` gives it to its child. The
probe runs each 30 s also when other TCP flows succeed: one connect each 30 s. The test
`warp_probe_renews_a_session_with_no_tcp` uses a fake session whose probe fails: it passes. Plant:
no probe task; the test fails. Step 4 (`data_path` in `status`, the ready document and `warp
status`) is T-140: `Live::data_path` gives the value.

# T-069: `warp tun`: a SYN probe of the session, and `--session-max-age`

**Source:** the lab kit's report masque-session-tcp-blackhole.md, in
`docs/research/podnet/mwan-field.md`, section 2.3 (B1, fixes 2 and 3).
**Category:** defect
**Milestone:** M5
**Priority:** P1
**Effort:** L
**Status:** done

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

## Done

2026-11-06, commit 7382ff4 (`T-069: warp tun: a SYN probe of the session, and
--session-max-age`). `src/warp/tun/probe.rs`: the SYN from the tunnel address and port 61999 to
the target of `--probe` (an IPv4 target; an IPv6 target gives no probe), the filter of its answer,
and the RST for a SYN-ACK. `tun::run` sends the SYN each 30 s, takes the answer out before the TUN,
and ends after 3 probes with no answer; it also ends at `--session-max-age`. A TUN of `from_fd`
(the raw pod) has no address and no probe. `warp_tun_probe_takes_its_answer_out` and
`warp_tun_probe_ends_a_dead_session` test the probe; `warp_tun_takes_session_max_age` is in
`tests/commands.rs` (`tests/cli.rs` cannot grow). Control: before, `warp tun --session-max-age 60`
exits 64. No live run: this host has no TUN device for a test.

# T-070: `warp exec`, `warp shell` and `warp nc` find a running `warp up` with another state directory

**Source:** `docs/reports/field-report-2026-11-05.md`, items 3, 5 and 6;
`docs/research/podnet/mwan-field.md`, section 3 (F3, F5, F6, W-F3, rank 3).
**Category:** defect
**Milestone:** M5
**Priority:** P1
**Effort:** S
**Status:** done

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

## Done

2026-11-06, commit 0293f91 (`T-070: warp exec, warp shell and warp nc find a running warp up with
another state directory`). `src/warp/find.rs`: the order `--socket`, `PODNET_WARP_SOCKET`, the run
directory, the pointer file (`$XDG_RUNTIME_DIR/podnet/warp-up.json`, else
`podnet-<uid>/warp-up.json` in the temporary directory; mode 0600, owner check). `warp up` writes it
with the env file; `warp down` removes it. The error names each socket tried and the state
directory of the pointer file. The agent uses the same lookup. The stand-in of T-012 is not there,
so the test of the binary is `warp_nc_finds_warp_up_of_another_state_directory`
(`tests/commands.rs`): a SOCKS5 stand-in on a unix socket that only the pointer file names; `warp
nc -N` reaches a loopback echo through it. `warp_exec_finds_warp_up_of_another_state_directory` and
`the_lookup_order_of_the_warp_socket` are unit tests of `warp::find`. Control: without the pointer in
the candidates, these three tests fail. The variable and the pointer file are in
`src/manual/facts.rs`. A test of `warp exec` with a real `warp up` waits for the stand-in (T-012).

# T-071: `warp exec` and `warp shell` take `--backend`, name the backend in one line, and log the seccomp emulation

**Source:** `docs/reports/field-report-2026-11-05.md`, items 2 and 8 (request 2);
`docs/research/podnet/mwan-field.md`, section 3 (F2b, W-F2b, rank 4); the owner's ruling of
2026-11-05 (`docs/decisions.md`, Pod backend).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** done

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

## Done

2026-11-06, commit ee9b44c (`T-071: warp exec and warp shell take --backend and name the
backend`). `warp exec` and `warp shell` take `--backend auto|netns|seccomp` (default `auto`) and
give it to the pod (`src/warp/pod.rs`). `warp nc` does not take it; `--socket` stays. The new pod
option `--name-backend` writes one line on stderr that names the backend that runs (also after
`auto`) and its limits; `podnet -q` (`PODNET_NETNS_QUIET`) removes it. `podnet -v warp exec`
gives `-v` to the pod. With `-v`, the seccomp backend logs each socket that it makes as a socket
pair (`crates/podnet-netns/src/socket.rs`) and each `setsockopt` that it answers
(`crates/podnet-netns/src/sockopt.rs`). The order of `auto` does not change (T-113). The three
tests of Prove pass (`tests/pod_backend_line.rs` and a unit test in `src/warp/pod.rs`). Eleven
plants (no line, two lines, no quiet, no `--name-backend`, no backend, no `-v`, each log removed
or given with no `-v`) each made a test fail.

# T-072: `warp tun` sets `rp_filter` to 0 on its interface

**Source:** the lab kit's report warp-tun-rp-filter-strict.md, in
`docs/research/podnet/mwan-field.md`, section 2.3 (B2, rank 5).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

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

## Done

2026-11-06, commit fb151ca (`T-072: warp tun sets rp_filter to 0 on its interface`).
`src/warp/tun/rp_filter.rs`: 0 for the interface after the create, at each session (`tun::run`) and
2 s later; a warning when the larger of `conf.all` and `conf.IF` is not 0; `--keep-rp-filter`; the
ready document has `rp_filter`. `the_effective_rp_filter_is_the_larger_value` and
`warp_tun_writes_0_unless_it_keeps_the_value` (a fake `conf` tree) pass. Not done: the row in
`doctor` (`src/doctor.rs` is frozen until the take of `pod-services`), and the live step: this
session starts no workflow, and this host has no TUN device.

# T-073: `warp forward`: the pins of `--resolve`, and the list of forwards

**Source:** `docs/reports/field-report-2026-11-05.md`, items 4 and 8 (requests 4 and 5);
`docs/research/podnet/mwan-field.md`, section 3 (F4a, F4b, W-F4a, W-F4b, ranks 6 and 7).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** done

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

2026-11-06, podnet took `pod-dns` and `pod-services` (bf0c7ca, podcrates v0.5.0). The freeze of
`src/resolve.rs` ended. `src/resolve.rs` is now glue over the resolver of `pod-dns`, and the pins
are in its settings (`pod_dns::Settings::pinned`). The fix lands in podnet and needs no change of
`pod-dns`: `src/resolve.rs` gets `pinned(host)`, and the DNS of the WARP commands moves from
`src/warp/proxy.rs` to `src/warp/proxy/names.rs`. The text of `ps` moves from `src/main.rs` to
`src/instances/text.rs`. The test of `--list` is `warp_forward_list_prints_the_forwards_of_ps`.

## Done

2026-11-06, commit bbfe527 (`warp: the pins of --resolve come first, ps prints each forward, warp
forward --list (T-073)`). `pinned(host)` in `src/resolve.rs` gives the pins of `--resolve` and
`PODNET_RESOLVE`. `resolve_all` and `resolve` (`src/warp/proxy/names.rs`) return the pins before
a DNS query through the tunnel: `warp forward`, `warp proxy` and `warp nc`. `ps` prints each
forward of an array `forward` as `LISTEN -> TO` (`src/instances/text.rs`). `warp forward --list`
prints the forwards of the detached instances. Control on the code before the fix:
`warp_resolve_takes_the_pin_first` fails (6 DNS packets go into the stack),
`ps_prints_each_forward` fails (no row `LISTEN -> TO`),
`warp_forward_list_prints_the_forwards_of_ps` fails (exit 64, unexpected argument `--list`). After
the fix, the three pass, and `sh scripts/agent/check.sh` exits 0.

CI run 42253187093 and live run 42253174816 at 3bf268a: success.

# T-074: `warp export`: the reserved bytes in the file, `--check`, and a TCP probe on the WireGuard leg

**Source:** the lab kit's report warp-export-kernel-wg-data-path-degrades.md, in
`docs/research/podnet/mwan-field.md`, section 2.3 (B3, rank 9).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** L
**Status:** done

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

## Correction

2026-11-06: step 3 needs no probe in `WgKeepalive`. The leg of `--transport wireguard` is a
`MasqueSession` under the `WarpStack` of `Live`, and `Live::probed` (T-068) probes each such
stack; `warp tun` on the leg has the SYN probe of T-069. Measured: the test
`wireguard_probe_renews_a_dead_leg` (a stand-in front door that answers each handshake and drops
each data message) passes on the code before this change (`f88aacf`), and fails with no probe
(`probed(None)`: "no renewal" after 10 s). A probe in `WgKeepalive` would be a second probe of the
same path. The test stays as the proof of step 3. The flag of the entry, `warp tun --leg
wireguard`, is `--transport wireguard` in podnet.

## Done

2026-11-06, commit 3e57e0a (`T-074: warp export: the reserved bytes, --check, and the probe of
the WireGuard leg`). Step 1: the head of the wg-quick output (`RESERVED_NOTE` in
`src/warp/export.rs`), the help of `warp export` and `README.md`. Step 2: `warp export --check`
(`src/warp/export/check.rs`): the leg with the reserved bytes and the leg with zeros, each with a
TCP connect to the target of `--probe` in 5 s; exit 0 (`device ok`), 1 (`needs reserved bytes`)
or 69 (`device data path dead, use --new`); `--out` and `--delete` are refused. Step 3: see the
Correction. `cargo test --workspace -- a_seal_with_zero_reserved_differs_in_three_bytes
wireguard_probe_renews_a_dead_leg` passes; `export_check_tells_the_three_states` (a stand-in front
door for each verdict) and `warp_export_check_is_a_flag` (`tests/commands.rs`) pass;
`sh scripts/agent/check.sh` exits 0 (1012 tests passed). Control before the change: the two unit
tests of `check.rs` do not compile, `warp_export_check_is_a_flag` fails (unexpected argument
`--check`). Not run: `gh workflow run live.yml` (no network to WARP here); the step is in
`scripts/live-batch2.sh`.

CI run 42253187093 and live run 42253174816 at 3bf268a: success (the live step of `warp export --check` ran).

# T-075: The datagram socket of the vnet shim takes the same user only

**Source:** `docs/maintenance.md`, section "Open work" (the bullet of the vnet shim UDP);
`docs/virtual-network.md`.
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

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

## Done

2026-11-06, commit 55e8570 (`T-075: the datagram socket of the vnet shim takes the same user
only`). The shim sets `SO_PASSCRED` on each datagram socket, and before `recvfrom` and `recvmsg` it
drops each datagram of another user (`MSG_PEEK` of `SCM_CREDENTIALS`), with one line on stderr.
`recv` and `read` are not interposed (written in `docs/virtual-network.md`). The test is
`tests/shim_datagram_user.rs`: as root, uid 65534 sends first, then root; the server gets the
datagram of root. Control: with the shim before, the server gets the datagram of uid 65534.

# T-076: A CI job runs the tests with the loopback down

**Source:** `docs/maintenance.md`, section "Open work" (#217).
**Category:** chore
**Milestone:** M5
**Priority:** P3
**Effort:** S
**Status:** done

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

## Done

2026-11-06, commit 2ddb0ed (`T-076: a CI job runs the tests with the loopback down`). The job
`no-loopback` of `ci.yml` builds the tests, then runs them with `sudo unshare -n` and `setpriv` as
the runner user, offline; its plant step removes `need_loopback!()` from one test and must see the
test fail. `the_kernel_refuses_a_real_af_inet_bind` now skips on `EADDRNOTAVAIL`. CI run 42183709673
(head 00ca0a5): the job `no-loopback` passed, with its plant step.

# T-077: An ingress `path:` rule matches the decoded path, as cloudflared does

**Source:** `docs/maintenance.md`, section "Open work" (`path:`, #289).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

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

## Done

2026-11-06, commit 7fe9a2c (`T-077: an ingress path: rule matches the decoded path, as cloudflared
does`). Step 1: `FindMatchingRule` of cloudflared (`ingress/ingress.go`) gives `requestURL.Path`,
the decoded path of Go: the premise holds. `PathPattern::is_match` decodes `%XX` (a `%` with no
two hex digits stays; `+` stays) and keeps the match with no anchor. `README.md` says both.
`a_path_rule_matches_the_decoded_path` passes; on the code before, `/a%20b` does not match.

# T-078: `pod doctor` uses the verdict words of `doctor` and has a `schema` key

**Source:** `docs/maintenance.md`, section "Open work" (`podnet pod doctor`); the owner's ruling of
2026-11-04 (`docs/decisions.md`, Doctor).
**Category:** defect
**Milestone:** M5
**Priority:** P3
**Effort:** S
**Status:** done

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

## Done

2026-11-06, commit 43b3559 (`T-078: pod doctor uses the verdict words of doctor and has a schema
key`). `crates/podnet-netns/src/doctor.rs`: `ok` or `fail` for each probe and backend; the JSON
form has `schema` 1, `verdict` for each capability and `verdicts`; the old keys stay; exit 3 stays.
The test is in `tests/commands.rs` (`tests/cli.rs` cannot grow) and passes. The `## Breaking` list
is in the draft note `docs/releases/v0.4.0-beta.1.md`.

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
**Status:** done

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

## Done

2026-11-06, commit 7e3d835 (`T-080: an error of an ingress rule names the line of the rule`).
`yaml::item_lines` gives the line of each item of a top-level list; each error of an ingress rule
names `ingress rule N (line L)`. A full map of positions in `src/yaml.rs` is not made: the errors
of the top-level keys name the key, which is unique in the file. `a_config_error_names_its_line`
passes; `cargo check --manifest-path fuzz/Cargo.toml --bins` passes.

# T-081: The tailnet front door warns when `tailscaled` is not logged in

**Source:** `docs/maintenance.md`, section "Open work" (#181 item 6);
`docs/research/podnet/podssh.md`, section 2.3, step 1.
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

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

## Done

2026-11-06, commit 3807970 (`T-081: the tailnet front door warns when tailscaled is not logged
in`). `Dialer::backend_state` reads `BackendState` of `/localapi/v0/status` (HTTP/1.0, 3 s, 4 MiB).
The door reads it at its start and after each failed dial, and warns one time when it is not
`Running`, with `tailscale up`. `tailscale_front_door_warns_when_logged_out` passes with a fake
LocalAPI that answers `NeedsLogin`. Not done: step 3 (the state in a doctor of the door): the doctor
of `podnet-netns` has no row for the door. The check against a real `tailscaled` waits for T-114.

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

# T-138: live: two runs in a row failed on the edge and WARP services (GitHub #316)

**Source:** GitHub #316 (the job report of `live`).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The issue: "The workflow live failed in two runs in a row." The failed runs:

- 42060806281 (a2af228), the step "Throughput of the HTTP path and of a --forward WebSocket": the
  edge answered `Unauthorized: Tunnel not found` to the registration of a tunnel that the step
  made some seconds before; `the tunnel is not ready after 90 s`.
- 42062631365 (542f40b), the step "Throughput through WARP, 1 to 16 MiB": the origin server of
  the script got `OSError: [Errno 98] Address already in use`, and the POST of 1 MiB got HTTP 530
  from the edge.

## Premise

- a2af228 changed only `version` beside the git dependencies of `Cargo.toml`. 542f40b changed only
  documents and the record. The code is the code of a5894fe, whose live run 42058519485 passed.
- The next live run 42064698302 (66c9512) passed each step.
- Not measured: the cause on the side of the edge (the time until a new named tunnel is known to
  the edge) and the process that held the port of the origin server.

## Approach

1. Read the failed step of each run (`docs/maintenance.md`, The issue loop).
2. Compare with the runs before and after.
3. The watches of the services move to `pod-services` (`docs/decisions.md`, Services crate): the
   wait for a new tunnel goes there, with no change in podnet now.

## Prove

```sh
curl -qfsS "https://forge.web.pkgforge.dev/github/repos/PodUtils/podnet/actions/runs/42064698302?n=$RANDOM"
```

## Done

2026-11-05, the commit of this Done section. Two failures of services in the live job, not of
the code: the live run 42064698302 of 66c9512 passed with the same code. The podcrates session
noted the "Tunnel not found" for the watches of `pod-services`.

# T-139: The start of a session changes the global git identity and can drop commits of main

**Source:** the podcrates session, 2026-11-06 (a fact that the owner found in the same script of
`PodUtils/podcrates`).
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`.claude/session-start.sh` ran `git config --global user.name` and `user.email`: it changed the
global git identity of a local machine. On a branch other than `main`, it ran
`git checkout -q -B main origin/main`: it reset an existing local `main` to `origin/main` and
dropped its commits that were not pushed.

## Premise

- `.claude/settings.json` gives the identity to each git command (`GIT_AUTHOR_*`,
  `GIT_COMMITTER_*`); the identity of the repository is enough for the rest.
- `PodUtils/podcrates` fixed its copy of the script (`.claude/session-start.sh` on its `main`).

## Approach

1. Take the script of podcrates: the identity of the repository only; an existing `main` is
   checked out as it is and only fast-forwarded (`git merge --ff-only origin/main`); a new `main`
   tracks `origin/main`; a tree with changes stays on its branch.
2. Test the three cases in clones of a scratch repository.

## Prove

```sh
sh -n .claude/session-start.sh
```

In a clone: a `main` with a commit that is not pushed keeps it; a tree with changes on a branch
stays there; a `main` behind `origin/main` moves forward; `git config --global user.email` does
not change.

## Done

2026-11-06, the commit of this Done section. The three cases passed in scratch clones: the
local commit of `main` stayed; the tree with changes stayed on its branch `work`; `main` moved
forward to the new commit of the origin. The global identity did not change.

# T-140: `data_path` and the time of the last TCP probe in `status`, the ready document and `warp status`

**Source:** T-068, step 4 of its Approach.
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The TCP probe of T-068 marks a session `tcp-dead` and renews it. Only the log shows it. A user of
`warp status`, `podnet status` or the ready document of `warp proxy` cannot see the state of the
data path or the time of the last probe.

## Premise

- Read: `Live::data_path` gives `ok` or `tcp-dead` (`src/warp/live.rs`).
- Read: `warp status` runs in another process than `warp proxy`; it reads files and the socket of
  the instance, not the memory of the proxy.
- `src/warp/proxy.rs` and `src/main.rs` are in `scripts/size-allow.txt` and cannot grow.

## Approach

1. Keep the time of the last probe and its result in `Live`.
2. Put `data_path` and `last_probe` in the ready document of `warp proxy` and `warp up`.
3. Give them to `warp status` and `podnet status` through the record of the instance (or a
   status file in the run directory).

## Decision

2026-11-06: the record of the instance, not a status file. `warp status`, `podnet status`,
`podnet ps` and `warp up` read the record already, and a renewal changes no path. The first
`Live` of the process (the session of `warp proxy`) writes `data_path` and `last_probe` (Unix
seconds) in the ready document of its record after each probe and when a new session opens
(`src/warp/live/instance.rs`). The write reads the record from the disk first
(`detach::update_record`), as `planned_end` and `retry_after` do. A process that is not an
instance writes nothing.

## Prove

```sh
cargo test --workspace -- warp_status_names_the_data_path
```

The test starts a fake session whose probe fails and reads `tcp-dead`, then `ok` after the new
session.

## Done

2026-11-06, commit da611f5 (`warp: data_path and last_probe in the record, warp status and podnet
status (T-140)`). `Live` keeps a `Report` (`data_path`, `last_probe` in Unix seconds). The first
`Live` of a process writes it in the ready document of its instance record after each probe and
at each new session (`src/warp/live/instance.rs`). The ready document of `warp proxy` and `warp
up`, `warp status` (text and `--json`) and `podnet status` show the two keys.
`cargo test --workspace -- warp_status_names_the_data_path` passes; with
`the_ready_document_names_the_data_path` and `status_names_the_data_path_of_an_instance`. Control:
with the report and the record writes disabled, the three tests fail (no `data_path`).
`sh scripts/agent/check.sh`: each check 0.

CI run 42259197563 and live run 42259203680 at 0c4ff75: success.

# T-141: live: two runs in a row failed after the take of pod-dns and pod-services (GitHub #325)

**Source:** GitHub #325 (the job report of `live`).
**Category:** defect
**Milestone:** M5
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The issue: "The workflow live failed in two runs in a row." The failed runs:

- 42210655807 (1301fb6, schedule), the step "Quick tunnel with no system DNS, then with 1.1.1.1
  blocked": the step read the lines `podnet::resolve` with `step=` and `server=`, which the take
  of `pod-dns` (bf0c7ca) removed.
- 42222905277 (61c70aa, a run by hand), the step "WARP run with the netns-raw backend": `warp run
  --backend netns-raw` panicked at `src/main.rs` (index 0 of an empty list): the nameservers of
  `cloudflare-dns` were empty after the take of `pod-services`.

## Premise

- The DNS step passed in run 42222905277 after c970da1 (it reads `source="doh"` of `pod_dns`).
- The endpoints `udp-1` and `udp-2` of `cloudflare-dns` give the address as the host, with no list
  of addresses; `Endpoint::ip_addrs` of `pod-services` reads the list only.

## Approach

1. Read the debug line of `pod_dns` in the DNS step (c970da1). Ask podcrates to name the DoH server
   (COORD-004, #322), and restore the check of the server with its release.
2. Read the addresses of an endpoint with `socket_addrs` (`services::ips_of`, 3db91c7), with a
   test.
3. Run `live.yml` at the head of `main` (#326).

## Prove

```sh
cargo test --workspace -- the_nameservers_of_the_service_are_1_1_1_1_and_1_0_0_1
```

The live run of #326 passes each step.

## Done

2026-11-06, commits c970da1 (the DNS step reads `pod_dns`) and 3db91c7 (`services::ips_of`: the
nameservers of `cloudflare-dns` are not empty). `the_nameservers_of_the_service_are_1_1_1_1_and_1_0_0_1`
passes; the control gives `[]`. Live run 42226303514 at 3db91c7: success, each step. CI run
42222918056 at 61c70aa: success. The check of the DoH server comes back with the next podcrates
tag (#322). GitHub #325 is closed with this evidence.

