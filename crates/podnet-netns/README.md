# podnet-netns

`podnet-netns` runs a program with all its network traffic sent through an
upstream: a SOCKS5 proxy, an HTTP `CONNECT` proxy, a chain of proxies, or a
tailnet through `tailscaled`. It does not use `LD_PRELOAD`. The kernel enforces
the redirection, so static binaries, Go binaries and programs that do not use
libc `connect(3)` get the same treatment.

`podnet-netns` is a library. `podnet pod` is its command line.

```sh
podnet pod -x socks5://127.0.0.1:1080 -- curl https://example.com
podnet pod -x socks5://unix:/run/proxy.sock -- ./static-binary
podnet pod -x socks5://hop1:1080 -x socks5://hop2:1080 -- ssh host
podnet pod -x tailscale:/run/tailscale/tailscaled.sock -- curl http://100.64.0.5/
podnet pod doctor --json
```

## Options

| Option | Function |
| --- | --- |
| `-x, --proxy SPEC` | An upstream. Repeat it to make a chain. Forms: `socks5://[user:pass@]host:port`, `http://[user:pass@]host:port`, `socks5://unix:/path`, `http://unix:/path`, `tailscale:/path/to/tailscaled.sock`. Default: `$ALL_PROXY`, `$HTTPS_PROXY` or `$HTTP_PROXY`. A SOCKS5 user or password longer than 255 bytes is an error (the limit of RFC 1929). A SOCKS5 target name longer than 255 bytes is refused. |
| `-r, --rule SPEC` | A route for some destinations: `domain:NAME=PROXY`, `domain:.NAME=PROXY` (the name and each name under it) `cidr:ADDR/PREFIX=PROXY` (IPv4 or IPv6) or `cidr:@FILE=PROXY` (one prefix on each line of FILE; `#` starts a comment). PROXY can be `direct` (TCP from podnet-netns, no proxy). The first rule that matches is used. |
| `--map NAME=ADDR` | Resolve `NAME` to `ADDR`, with no upstream. |
| `--backend NAME` | `auto` (default), `netns` or `seccomp`. |
| `--prefer-udp` | With `auto`: `seccomp` first when it works, because it carries all UDP (`netns` carries DNS only). `podnet warp run` sets it. |
| `--keep-proxy-env` | Keep `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` and their lower-case forms for the program. By default the program does not get them: the pod is its egress, and a program that used them would send to a host proxy that it cannot reach. |
| `--inbound-dir DIR` | Seccomp backend only: where a port that the program listens on becomes a unix socket (`DIR/<port>.sock`). The default is `$XDG_RUNTIME_DIR/podnet-netns-inbound` when that directory is of the user, else `$TMPDIR/podnet-netns-inbound-<uid>`. A new directory gets mode 0700. A directory of another user, a symbolic link, or a directory that the group or others can write is refused (exit 3). With `--backend netns` it is a usage error (exit 64); when `auto` picks netns, a warning says that it is not used. |
| `--serve LISTEN` | Serve SOCKS5, HTTP `CONNECT` and UDP ASSOCIATE on `unix:/path` or `tcp://host:port`, through the `-x` chain. |
| `-v, --verbose` | Log each flow. |

`podnet pod doctor` prints what the host permits. The exit status is 3 when no
backend can run. The seccomp probe runs in a child process. It sets
`no_new_privs` before it installs its filter, as the backend does: an
unprivileged process cannot install the filter without it.

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
* The parent runs a `smoltcp` stack on the TUN. For each SYN of the program,
  it dials the upstream first, in a task. When the dial succeeds, the stack
  accepts the connection and copies the bytes. When the dial fails (a dead
  proxy, a 407 of the proxy), the program gets a RST, and its `connect()`
  fails with `ECONNREFUSED`. The program cannot read the HTTP status of the
  proxy; `-v` prints it.
* The parent answers each UDP query to port 53, to any resolver address, from
  the fake-IP pool. The answer comes from the address that the program sent
  the query to.

Needs: unprivileged user namespaces and `/dev/net/tun`. This backend carries
TCP and DNS. It does not carry other UDP, and no backend of the pod carries
ICMP (`ping`).

A listener of the program (for example `podnet connect -L tcp://127.0.0.1:8080`)
is in the network namespace of the pod: a process outside the pod does not
see it. Use a unix socket for it (`-L unix:///path`).

### seccomp

* A helper thread sets `no_new_privs`, installs a `SECCOMP_RET_USER_NOTIF`
  filter, and forks the child. Thus the supervisor threads have no filter.
* The filter stops: `socket`, `connect`, `bind`, `listen`, `accept`, `accept4`,
  `sendto`, `sendmsg`, `sendmmsg`, `recvfrom`, `recvmsg`, `setsockopt`,
  `getsockopt`, `getsockname`, `getpeername`, `close`, `io_uring_setup`,
  `io_uring_enter`, `io_uring_register`. A system call of a foreign ABI (i386 or x32 on x86_64)
  gets `ENOSYS`.
* `socket(AF_INET | AF_INET6)` gets one end of a socketpair, installed with
  `SECCOMP_IOCTL_NOTIF_ADDFD`. Thus `read`, `write`, `poll` and `epoll` work on
  a real descriptor.
* The supervisor keeps one entry for each socket of the program. The key is
  the inode of the socket (`/proc/<pid>/fd/<n>` gives `socket:[INODE]`), so a
  copy made by `fork`, `dup`, `dup2`, `dup3` or `fcntl(F_DUPFD)` finds the
  entry. A `close` removes the entry only when no other descriptor of the pod
  refers to the socket. A sweep removes the entries of sockets that closed
  with no `close` call (the exit of a process, `close_range`).
* `connect` is answered after the supervisor dials the upstream. The
  supervisor reads the address from `/proc/<pid>/mem` of the calling task. It
  opens that file again for each notification, and it checks the notification
  with `SECCOMP_IOCTL_NOTIF_ID_VALID` after the open. A connect that fails
  gives `ECONNREFUSED`. Then `getsockopt(SO_ERROR)` gives `ECONNREFUSED`
  one time, and 0 after that, as the kernel does.
* `bind`, `listen` and `accept` make a unix listener in `--inbound-dir`. The
  listener fd of the program is readable while a connection waits, so
  `poll`, `select` and `epoll` wake for it. A non-blocking `accept` with no
  connection gets `EAGAIN`; a blocking `accept` waits without stopping the
  other system calls of the program. The peer address of an accepted
  connection is not known (the client is a unix socket).
* UDP to port 53 is answered from the fake-IP pool. Other UDP goes through
  SOCKS5 UDP ASSOCIATE. `sendmmsg` sends all messages when the supervisor can
  write `msg_len` into the child. Else it sends one message and returns 1.
  glibc does not send the other messages, so the seccomp backend adds
  `single-request` to `RES_OPTIONS` of the program: glibc then sends the A
  and the AAAA query in two calls (issue 113). A program that clears its
  environment loses this option.
* The supervisor checks each length that the program gives before it reads
  the memory of the program. A datagram that does not fit in one SOCKS5 UDP
  datagram of 65507 bytes (the header and the payload) gets `EMSGSIZE`, as
  the kernel gives for a datagram that is too large. A `msghdr` with more
  than 1024 iovecs also gets `EMSGSIZE`. A buffer that cannot be read gets
  `EFAULT`.
* `recvfrom` and `recvmsg` on an unconnected UDP socket give the source
  address of the datagram, not the `AF_UNIX` address of the socketpair. The
  source is the address that the program sent to: the fake IP of a name
  also when the proxy answers from the address of the host, and the address
  of the resolver for a DNS answer. The supervisor reads the datagram from
  the socketpair and writes the data, the address and its length into the
  memory of the program. `MSG_PEEK`, `MSG_TRUNC` and `MSG_DONTWAIT` work. A
  blocking read waits without stopping the other system calls of the
  program. These reads stay direct: a read of a connected socket, a read of
  a socket that is not of the pod, `read`, `recvmmsg`, and each read when
  the host refuses writes to the memory of the program. A `recvfrom` with
  no source buffer (`recv`, the usual read of a TCP program) does not go
  through the supervisor: the kernel runs it. Each other `recvfrom` and each
  `recvmsg` goes through the supervisor, also a read of a TCP socket, which
  the supervisor passes on at once.
* With a proxy on a unix socket, UDP goes on the control connection first
  (SOCKS5 command `0x83`, "UDP in the stream"). The supervisor then needs no
  kernel UDP socket, and a host that refuses `AF_INET` sockets keeps UDP. A
  proxy that answers `0x07`, or closes, gets UDP ASSOCIATE.
* `io_uring` is refused with `EPERM`, because its operations do not go through
  the filter.
* A TCP socket keeps its entry in the supervisor after its `connect`
  (`src/sockopt.rs`). `setsockopt` gives 0 and the supervisor keeps the
  value; `getsockopt` gives the value that the program set (for example
  `TCP_NODELAY` and `TCP_KEEPIDLE`). `getpeername` gives the address and
  the port of the `connect` (a name keeps its fake address); a stream with
  no `connect` gives `ENOTCONN`. `getsockname` gives the bound address,
  else the unspecified address of the family with an ephemeral port.
* `getsockname` and `getpeername` give the logical address. The supervisor
  writes it into the child memory through `/proc/<pid>/mem`, else with
  `process_vm_writev`. As the kernel does, it writes at most the length that
  the caller gives, and it sets the length to the full size of the address. When the host refuses both, the calls fail with
  `EOPNOTSUPP` (not the `AF_UNIX` address of the socketpair), the pod prints
  a warning once, and `pod doctor` shows the row `write program memory` as
  `no`. A QUIC client (`curl --http3`) then fails; `curl --http3` falls back
  to HTTP/2. A program that reads its own address can crash: for example a
  Go program with a type assertion on `LocalAddr()`. Use `--backend netns`
  where the host permits it. No other way gives the address to the program
  without a write to its memory.
* An errno of the supervisor is a failure of the system call (-1 and the
  errno), for example `EPERM` for `io_uring_setup`.
* After the child exits, the supervisor waits up to 3 seconds for the relays
  to finish.

Needs: seccomp with `SECCOMP_RET_USER_NOTIF` (Linux 5.0 or newer).

### UDP in the stream (SOCKS5 command `0x83`)

The request is a SOCKS5 request with the command `0x83` and the address
`0.0.0.0:0`. The reply is a SOCKS5 reply. After a reply of `0x00`, each
datagram in each direction is one frame on the same connection:

| Bytes | Field |
| --- | --- |
| 2 | The length of the datagram, big endian |
| N | A SOCKS5 UDP datagram (RFC 1928, section 7): header and payload |

The association ends when the connection closes. `podnet warp proxy` and
`podnet pod --serve` serve the command. A server that does not know it
answers `0x07`.

## DNS

Both backends answer A queries from the pool `198.18.0.0/15`. The same name
always gets the same address. With the `seccomp` backend, AAAA queries get
an address of the ULA prefix `fd63:6672:7300::/96` that holds the same pool
address, so `getaddrinfo(AF_INET6)` works. The `netns` backend (IPv4 only)
answers AAAA with no address. When the program connects to a pool address
of either family, the upstream gets the name (SOCKS5 `ATYP=3`, or the
`CONNECT` host), so the upstream resolves it. A name of `--map` gets no
AAAA answer.

## Library

```rust
// Run the command line in this process. Return the exit status.
let status = podnet_netns::main_with_args(&["-x".into(), "socks5://127.0.0.1:1080".into(),
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
