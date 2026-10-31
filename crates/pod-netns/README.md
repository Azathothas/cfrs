# pod-netns

`pod-netns` runs a program with all its network traffic sent through an
upstream: a SOCKS5 proxy, an HTTP `CONNECT` proxy, a chain of proxies, or a
tailnet through `tailscaled`. It does not use `LD_PRELOAD`. The kernel enforces
the redirection, so static binaries, Go binaries and programs that do not use
libc `connect(3)` get the same treatment.

`pod-netns` is a CLI and a library. `cfrs pod` runs the same code.

```sh
pod-netns -x socks5://127.0.0.1:1080 -- curl https://example.com
pod-netns -x socks5://unix:/run/proxy.sock -- ./static-binary
pod-netns -x socks5://hop1:1080 -x socks5://hop2:1080 -- ssh host
pod-netns -x tailscale:/run/tailscale/tailscaled.sock -- curl http://100.64.0.5/
pod-netns doctor --json
```

## Options

| Option | Function |
| --- | --- |
| `-x, --proxy SPEC` | An upstream. Repeat it to make a chain. Forms: `socks5://[user:pass@]host:port`, `http://[user:pass@]host:port`, `socks5://unix:/path`, `tailscale:/path/to/tailscaled.sock`. Default: `$ALL_PROXY`, `$HTTPS_PROXY` or `$HTTP_PROXY`. |
| `-r, --rule SPEC` | A route for some destinations: `domain:NAME=PROXY` or `cidr:ADDR/PREFIX=PROXY`. The first rule that matches is used. |
| `--map NAME=ADDR` | Resolve `NAME` to `ADDR`, with no upstream. |
| `--backend NAME` | `auto` (default), `netns` or `seccomp`. |
| `--inbound-dir DIR` | Where a port that the program listens on becomes a unix socket (`DIR/<port>.sock`). |
| `--serve LISTEN` | Serve SOCKS5, HTTP `CONNECT` and UDP ASSOCIATE on `unix:/path` or `tcp://host:port`, through the `-x` chain. |
| `-v, --verbose` | Log each flow. |

`pod-netns doctor` prints what the host permits. The exit status is 3 when no
backend can run.

## Backends

`--backend auto` uses `netns` when the host permits `unshare`, else `seccomp`.

### netns

* The child calls `unshare(CLONE_NEWUSER | CLONE_NEWNET)` (or
  `CLONE_NEWNET` with privileges). The parent writes the uid and gid maps.
* The child brings up `lo` and makes a TUN device with `ioctl` calls (not with
  `ip`), then gives the TUN descriptor to the parent with `SCM_RIGHTS`.
* The parent runs a `smoltcp` stack on the TUN. It accepts each TCP flow, dials
  the upstream in a task, and copies the bytes.
* The parent answers each UDP query to port 53, to any resolver address, from
  the fake-IP pool. The answer comes from the address that the program sent
  the query to.

Needs: unprivileged user namespaces and `/dev/net/tun`. This backend carries
TCP and DNS. It does not carry other UDP.

### seccomp

* A helper thread sets `no_new_privs`, installs a `SECCOMP_RET_USER_NOTIF`
  filter, and forks the child. Thus the supervisor threads have no filter.
* The filter stops: `socket`, `connect`, `bind`, `listen`, `accept`, `accept4`,
  `sendto`, `sendmsg`, `sendmmsg`, `setsockopt`, `getsockopt`, `getsockname`,
  `getpeername`, `close`, `io_uring_setup`, `io_uring_enter`,
  `io_uring_register`. A system call of a foreign ABI (i386 or x32 on x86_64)
  gets `ENOSYS`.
* `socket(AF_INET | AF_INET6)` gets one end of a socketpair, installed with
  `SECCOMP_IOCTL_NOTIF_ADDFD`. Thus `read`, `write`, `poll` and `epoll` work on
  a real descriptor.
* `connect` is answered after the supervisor dials the upstream. The
  supervisor reads the address from `/proc/<pid>/mem` of the calling task. It
  opens that file again for each notification, and it checks the notification
  with `SECCOMP_IOCTL_NOTIF_ID_VALID` after the open.
* `bind`, `listen` and `accept` make a unix listener in `--inbound-dir`.
* UDP to port 53 is answered from the fake-IP pool. Other UDP goes through
  SOCKS5 UDP ASSOCIATE. `sendmmsg` sends all messages when the supervisor can
  write `msg_len` into the child. Else it sends one message and returns 1, and
  the caller sends the others.
* `io_uring` is refused with `EPERM`, because its operations do not go through
  the filter.
* `getsockname` and `getpeername` give the logical address when the supervisor
  can write into the child memory. Else the kernel answer (an `AF_UNIX`
  address) is returned.
* After the child exits, the supervisor waits up to 3 seconds for the relays
  to finish.

Needs: seccomp with `SECCOMP_RET_USER_NOTIF` (Linux 5.0 or newer).

## DNS

Both backends answer A queries from the pool `198.18.0.0/15`. The same name
always gets the same address. AAAA queries get an empty answer, so programs
use IPv4. When the program connects to a pool address, the upstream gets the
name (SOCKS5 `ATYP=3`, or the `CONNECT` host), so the upstream resolves it.

## Library

```rust
// Run the command line in this process. Return the exit status.
let status = pod_netns::main_with_args(&["-x".into(), "socks5://127.0.0.1:1080".into(),
                                         "--".into(), "curl".into(), "https://example.com".into()]);
```

The public modules are also used alone:

| Module | Contents |
| --- | --- |
| `upstream` | Proxy specs, rules, SOCKS5 and HTTP `CONNECT` clients, chains, UDP ASSOCIATE. |
| `socks` | The server side of SOCKS5 and HTTP `CONNECT`. |
| `dns` | DNS query and answer encoding. |
| `listen` | `unix:/path` and `tcp://host:port` listen addresses. |
| `tailscale` | A dialer for the `ts-dial` endpoint of the `tailscaled` LocalAPI, and a SOCKS5 front door for it. |

## Tests

`tests/seccomp.rs` compiles small C programs (static and dynamic) and runs them
with both backends. A backend that the host does not permit is skipped. Each
test program has a 10-second alarm, so a lost reply fails the test.
