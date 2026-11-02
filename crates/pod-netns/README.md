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
| `-x, --proxy SPEC` | An upstream. Repeat it to make a chain. Forms: `socks5://[user:pass@]host:port`, `http://[user:pass@]host:port`, `socks5://unix:/path`, `http://unix:/path`, `tailscale:/path/to/tailscaled.sock`. Default: `$ALL_PROXY`, `$HTTPS_PROXY` or `$HTTP_PROXY`. |
| `-r, --rule SPEC` | A route for some destinations: `domain:NAME=PROXY`, `domain:.NAME=PROXY` (the name and each name under it) or `cidr:ADDR/PREFIX=PROXY`. PROXY can be `direct` (TCP from pod-netns, no proxy). The first rule that matches is used. |
| `--map NAME=ADDR` | Resolve `NAME` to `ADDR`, with no upstream. |
| `--backend NAME` | `auto` (default), `netns` or `seccomp`. |
| `--prefer-udp` | With `auto`: `seccomp` first when it works, because it carries all UDP (`netns` carries DNS only). `cfrs warp run` sets it. |
| `--keep-proxy-env` | Keep `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` and their lower-case forms for the program. By default the program does not get them: the pod is its egress, and a program that used them would send to a host proxy that it cannot reach. |
| `--inbound-dir DIR` | Seccomp backend only: where a port that the program listens on becomes a unix socket (`DIR/<port>.sock`). With `--backend netns` it is a usage error (exit 64); when `auto` picks netns, a warning says that it is not used. |
| `--serve LISTEN` | Serve SOCKS5, HTTP `CONNECT` and UDP ASSOCIATE on `unix:/path` or `tcp://host:port`, through the `-x` chain. |
| `-v, --verbose` | Log each flow. |

`pod-netns doctor` prints what the host permits. The exit status is 3 when no
backend can run.

## Backends

`--backend auto` uses `netns` when the host permits `unshare`, else `seccomp`.
With the `seccomp` backend, a TCP connect to `127.0.0.0/8` does not go to
the proxy: it goes to a listener of the program itself (its inbound
socket) when there is one, else to TCP on the host.

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
* `bind`, `listen` and `accept` make a unix listener in `--inbound-dir`. The
  listener fd of the program is readable while a connection waits, so
  `poll`, `select` and `epoll` wake for it. A non-blocking `accept` with no
  connection gets `EAGAIN`; a blocking `accept` waits without stopping the
  other system calls of the program. The peer address of an accepted
  connection is not known (the client is a unix socket).
* UDP to port 53 is answered from the fake-IP pool. Other UDP goes through
  SOCKS5 UDP ASSOCIATE. `sendmmsg` sends all messages when the supervisor can
  write `msg_len` into the child. Else it sends one message and returns 1, and
  the caller sends the others.
* With a proxy on a unix socket, UDP goes on the control connection first
  (SOCKS5 command `0x83`, "UDP in the stream"). The supervisor then needs no
  kernel UDP socket, and a host that refuses `AF_INET` sockets keeps UDP. A
  proxy that answers `0x07`, or closes, gets UDP ASSOCIATE.

### UDP in the stream (SOCKS5 command `0x83`)

The request is a SOCKS5 request with the command `0x83` and the address
`0.0.0.0:0`. The reply is a SOCKS5 reply. After a reply of `0x00`, each
datagram in each direction is one frame on the same connection:

| Bytes | Field |
| --- | --- |
| 2 | The length of the datagram, big endian |
| N | A SOCKS5 UDP datagram (RFC 1928, section 7): header and payload |

The association ends when the connection closes. `cfrs warp proxy` and
`pod-netns --serve` serve the command. A server that does not know it
answers `0x07`.
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

## DNS of the program (netns backend)

The netns backend gives the program a private `/etc/resolv.conf` with
`nameserver 10.66.255.254` (the gateway of the TUN, where the pod answers
DNS): a bind mount in a mount namespace of the program, so the file of the
host stays as it is. The resolver of the host (for example `127.0.0.53`) is
on the loopback of the host, which the namespace of the program does not
have. When the mount fails, a warning says so and the program keeps the file
of the host. The seccomp backend reads the DNS packets of the program
itself, with any resolver file.
