This file holds the entries of milestone M7: pods that live past their first program, generic
UDP in the netns backend, and the netns backend as the first choice of `warp exec`. Sources: the
field report of 0.3.0-beta.12 (`docs/reports/field-report-2026-11-05.md`, item 1);
`docs/research/podnet/mwan-field.md`, section 3 (W-F1, rank 8); `docs/research/podnet/vn.md`,
section 3.1 (P1, P2). An entry that changes the backends lands before the split of T-040
starts, or after it ends.

# T-107: seccomp: the pod lives past its first program

**Source:** `docs/reports/field-report-2026-11-05.md`, items 1 and 8 (request 1);
`docs/research/podnet/mwan-field.md`, section 3 (F1, W-F1, part a).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The pod ends when its first program exits. A program that starts a daemon (`rad node start`
starts `radicle-node`) loses the network of the daemon when the starter exits. The reporter
called this the highest cost of the session.

## Premise

- Read: `supervise_seccomp` sets `shutdown` when `waitpid` returns for the first child, drains
  the relays for `RELAY_DRAIN`, and exits (`crates/podnet-netns/src/seccomp.rs`).
- The notification descriptor gives POLLHUP when no task uses the filter.

## Approach

1. When the first child exits and other tasks still use the filter, return the exit code of the
   first child to the caller at once.
2. Keep a supervisor in a forked process until POLLHUP of the notification descriptor.

## Prove

```sh
cargo test --test pod_seccomp -- seccomp_pod_outlives_its_first_child
```

A C program starts a daemon and exits 0. The daemon connects after 2 s through the pod, and the
connect succeeds.

## Start condition

T-063 is done.

# T-108: netns: the pod lives past its first program

**Source:** `docs/research/podnet/mwan-field.md`, section 3 (F1, W-F1, part a).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

The netns backend ends its router when the first program exits, as the seccomp backend does
(T-107).

## Premise

- Read: the netns backend returns when `waitpid` returns for its child
  (`crates/podnet-netns/src/netns.rs`).

## Approach

1. Return the exit code of the first child at once.
2. Keep the router of the namespace while a process lives in it: keep a reaper as process 1 of
   the namespace, and end when it has no child.

## Prove

```sh
cargo test --workspace -- netns_pod_outlives_its_first_child
```

# T-109: `warp exec --detach --name N` keeps a pod under the supervisor

**Source:** `docs/reports/field-report-2026-11-05.md`, items 1 and 8 (request 1);
`docs/research/podnet/mwan-field.md`, section 3 (W-F1, part b).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

`warp exec` has no `--detach`. A daemon in a pod has no supervisor, no name in `ps`, and no logs.

## Premise

- `src/detach.rs` and `src/instances.rs` supervise the other server commands: `ps`, `stop`,
  `logs` and `wait`.
- Read: the arguments of `warp exec` have no detach options (`src/main.rs`).

## Approach

1. Add `--detach`, `--name` and the restart options to `warp exec`.
2. Run the pod under the supervisor. `ps` lists it, `stop N` ends it, and `logs N` shows its
   output.

## Prove

```sh
cargo test --test detach -- warp_exec_detach_lists_the_pod
```

The test uses the stand-in of T-012.

## Start condition

T-107 and T-108 are done.

# T-110: `warp exec --join N` runs a command in a detached pod

**Source:** `docs/reports/field-report-2026-11-05.md`, item 1;
`docs/research/podnet/mwan-field.md`, section 3 (W-F1, part c).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

A second `warp exec` gets a new pod. The client of a daemon cannot reach the loopback listeners
or the names of the pod of the daemon.

## Premise

- The seccomp backend has no namespace. It keeps the loopback listeners of a pod in its inbound
  directory, and its names in its fake DNS.
- The netns backend has a user and a network namespace for each pod.

## Approach

1. Add `warp exec --join N -- CMD`.
2. seccomp: use the inbound directory and the fake DNS state of the session N.
3. netns: enter the user and the network namespace of the session N with `setns`.

## Prove

```sh
cargo test --workspace -- warp_exec_join_reaches_a_listener_of_the_pod
```

The test runs with each backend.

## Start condition

T-109 is done.

# T-111: netns: generic UDP

**Source:** `docs/research/podnet/vn.md`, section 3.1 (P2) and 3.6;
`docs/research/podnet/mwan-field.md`, section 5 (question 3).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** M
**Status:** open

## Problem

The netns backend relays UDP to port 53 only. The seccomp backend relays each UDP flow, but it
emulates the sockets. Thus a user must choose between UDP and correct socket calls.

## Premise

- Read: `answer_dns` takes the DNS datagrams from the TUN before smoltcp
  (`crates/podnet-netns/src/netns.rs`).
- The upstream chain carries UDP in the stream with 0x83 frames
  (`crates/podnet-netns/src/upstream.rs`).
- A smoltcp UDP socket for each port loses datagrams of two flows to one port (the defect of the
  vn kit).

## Approach

1. Keep a table of flows by source and destination, with a reap after an idle time and a cap.
2. Take each datagram from the TUN before smoltcp, as `answer_dns` does. Build each reply as a
   packet with the addresses swapped.
3. Carry the datagrams in the stream of the upstream, else with SOCKS5 UDP ASSOCIATE. Send a
   name of the fake DNS as a name.
4. Add a test that a datagram of zero bytes survives the frame code.

## Prove

```sh
cargo test --workspace -- netns_backend_relays_udp netns_backend_relays_udp_in_the_stream netns_two_flows_to_one_port_lose_nothing netns_udp_flow_is_reaped an_empty_datagram_survives
```

# T-112: netns: the gateway address reaches the loopback of the host, when the user asks

**Source:** `docs/research/podnet/vn.md`, sections 3.1 (P1) and 5 (question 1).
**Category:** feature
**Milestone:** M7
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

A netns pod cannot reach a service on the loopback of the host. podman and slirp4netns give a
gateway address for it.

## Premise

- The gateway of the TUN of the pod is fixed (`crates/podnet-netns/src/netns.rs`).
- A map of the gateway to the host loopback lets the pod reach each service on 127.0.0.1 of the
  host.

## Approach

1. Add `--host-gateway`, off by default.
2. With it, a TCP connect to the gateway and a port connects 127.0.0.1 and that port on the host.
   A UDP datagram to the gateway (not port 53) goes to a UDP socket of the host.

## Prove

```sh
cargo test --workspace -- netns_host_gateway_reaches_the_host_loopback netns_without_host_gateway_is_refused
```

## Start condition

T-111 is done.

# T-113: `warp exec` and `warp shell` try the netns backend first

**Source:** the owner's ruling of 2026-11-05 (`docs/decisions.md`, Pod backend);
`docs/research/podnet/mwan-field.md`, section 5 (question 3); `docs/research/podnet/vn.md`,
section 5 (question 5).
**Category:** feature
**Milestone:** M7
**Priority:** P2
**Effort:** S
**Status:** open

## Problem

`warp exec` passes `--prefer-udp`, so `auto` takes the seccomp backend first, with its emulated
sockets.

## Premise

- Read: `src/warp/up.rs` passes `--prefer-udp`, and `crates/podnet-netns/src/lib.rs` orders the
  backends.
- After T-063 and T-064, the seccomp backend keeps TCP sockets correct. After T-111, the netns
  backend carries each UDP flow.

## Approach

1. Make `auto` of `warp exec` and `warp shell` try netns first, then seccomp when the user
   namespace or the TUN fails.
2. Make the line of T-071 name the backend and the reason of the choice.
3. Change the manual and `README.md`.

## Decision

The owner, 2026-11-05 (`docs/decisions.md`, Pod backend): after the fix of the TCP sockets of the
seccomp backend and generic UDP in the netns backend, `warp exec` and `warp shell` try the netns
backend first, then seccomp.

## Prove

```sh
cargo test --workspace -- warp_exec_tries_netns_first warp_exec_falls_back_to_seccomp
```

## Start condition

T-063, T-064, T-071 and T-111 are done.
