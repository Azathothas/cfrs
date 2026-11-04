# Virtual network (`cfrs net`, `cfrs::vnet`)

The virtual network gives programs IPv4 and IPv6 addresses on a host where the
kernel refuses `AF_INET` and `AF_INET6` binds. It needs no network namespace,
no TUN device and no capability. It needs only `AF_UNIX`, including the
abstract namespace.

Use `cfrs net doctor` to see what the host permits.

## 1. Parts

| Part | Module | Function |
| --- | --- | --- |
| Shim | `shim/cfrsnet.c`, `vnet::shim` | An `LD_PRELOAD` library. It changes `AF_INET` sockets into `AF_UNIX` abstract sockets. |
| Stack | `vnet::stack` | A `smoltcp` TCP/IP stack. It owns the virtual addresses. |
| Link | `vnet::device`, `vnet::framing` | The packet queues of the stack, and the framing for a byte stream. |
| Proxy | `vnet::proxy` | A SOCKS5 and HTTP `CONNECT` front door into the stack. |
| Switch | `vnet::switch` | A hub that connects stacks, and the fault injector. |
| Resolver | `vnet::dns` | A DNS server at the gateway for virtual names. |
| Policy | `vnet::policy` | Allow and deny rules, applied at connect time. |
| Capture | `vnet::record` | pcap capture and replay of the link. |
| Control | `vnet::control` | The protocol between the shim and the stack. |

## 2. Addresses

| Address | Use |
| --- | --- |
| `10.66.0.0/24`, `fd00:66::/64` | The virtual subnets. |
| `10.66.0.1` | The gateway. The virtual resolver listens on port 53. |
| `10.66.0.2` to `10.66.0.254` | Stacks and programs. |

The kernel does not see these addresses. `cfrs net addresses` prints the plan.

## 3. Shim

Build the shim and start a program with it:

```sh
cfrs net shim --out /tmp/cfrsnet --log
LD_PRELOAD=/tmp/cfrsnet/libcfrsnet.so ./server
```

### 3.1 Address translation

An IP endpoint becomes an abstract socket name:

```text
\0cfrsnet/<family>/<address>/<port>

10.66.0.2:8080   ->  \0cfrsnet/4/10.66.0.2/8080
[fd00::2]:443    ->  \0cfrsnet/6/fd00::2/443
```

The IPv6 address is in the RFC 5952 form. The longest name is 60 bytes.

### 3.2 Interposed calls

| Call | Action on a virtual descriptor |
| --- | --- |
| `socket` | Make an `AF_UNIX` socket of the same type. Mark the descriptor as virtual. `SOCK_RAW` gives `EAFNOSUPPORT`. |
| `bind`, `connect` | Translate the address to the abstract name. |
| `sendto`, `recvfrom`, `sendmsg`, `recvmsg` | Translate the datagram addresses. |
| `accept`, `accept4` | The new descriptor is virtual. The logical peer is recorded. |
| `getsockname`, `getpeername` | Return the logical address. Truncate to `*len` as Linux does. A null address gives the length. A stream client with no `bind` gets a local address at `connect` (the shim address and a port of 49152-65535), and the server sees it as the peer. |
| `setsockopt`, `getsockopt` | Record `IPPROTO_TCP` options (`TCP_NODELAY`, `TCP_KEEPIDLE`) and answer them. |
| `close`, `dup`, `dup2`, `dup3`, `fcntl(F_DUPFD*)` | Clear or copy the virtual state. |

`read`, `write`, `poll`, `epoll` and `shutdown` are not interposed. They work
on the real `AF_UNIX` descriptor.

### 3.3 Limits

* The shim cannot reach a static binary. Use `cfrs pod` or `cfrs net proxy`
  for such programs.
* `recvmmsg` and `io_uring` are not interposed.
* `/proc/net/tcp`, `getifaddrs` and `/sys/class/net` do not show the virtual
  addresses.
* An abstract name is global on the host (in one network namespace). Two
  programs that bind the same virtual address and port get `EADDRINUSE`.
* An abstract name has no file permissions. Each user of the host can bind
  or connect to it. Thus the shim takes the same user only (`SO_PEERCRED`):
  `accept` closes a client of another user and takes the next client, and
  `connect` to a listener of another user fails with `ECONNREFUSED`. A
  datagram socket of the shim has no such check.

## 4. Stack

`NetStack::loopback()` makes a stack whose link sends each packet back into the
stack. Programs and the proxy on one host use it.

`NetStack::over_link(config)` makes a stack whose packets go to
`link_out()` and come from `link_in()`. A pump moves the packets between the
queues and a byte stream. `vnet::switch::pump` is that pump.

* The clock is `std::time::Instant`. The stack waits on the inbound queue or on
  the next timer of `smoltcp`. It does not spin.
* On a byte stream, each packet has a 2-byte big-endian length in front of it
  (`vnet::framing`).
* The MTU is 1280 or more.

## 5. Modes

### 5.1 Direct (one host, no stack)

Two programs with the shim talk through the abstract name. No other process is
necessary.

```text
program A: bind 10.66.0.2:8080     ->  \0cfrsnet/4/10.66.0.2/8080
program B: connect 10.66.0.2:8080  ->  \0cfrsnet/4/10.66.0.2/8080
```

### 5.2 Proxy

`cfrs net proxy` puts a SOCKS5 and HTTP `CONNECT` front door on the stack.
`--forward VIRT=REAL` makes the stack listen on a virtual address and send each
connection to a real destination (`host:port` or `unix:/path`).

```sh
cfrs net proxy --listen unix:/tmp/cfrsnet.socks \
    --forward 10.66.0.2:8080=unix:/run/app.sock
```

A client must speak SOCKS5 over `AF_UNIX` itself, because `curl` does not
accept a unix-socket SOCKS proxy. On a host that permits a TCP bind, use
`--listen tcp://127.0.0.1:1080` and `ALL_PROXY=socks5h://127.0.0.1:1080`.

### 5.3 Switch (more than one host)

`cfrs net switch` is a hub for stacks. Each stack connects to it with a byte
stream. The switch records the source address of each peer. It sends each
packet to the peer that owns the destination address, and it sends a packet
for an unknown address to all other peers.

```sh
# Host S: the switch. Expose it with a tunnel when the hosts are far apart:
cfrs net switch --listen unix:/tmp/sw.sock
cfrs tunnel --forward unix:/tmp/sw.sock

# Host A: a stack at 10.66.0.2 with a service.
cfrs connect wss://<host>/__cfrs/ws -L unix:///tmp/sw.sock     # if remote
cfrs net proxy --switch unix:/tmp/sw.sock --address 10.66.0.2 \
    --forward 10.66.0.2:8080=unix:/run/app.sock

# Host B: a stack at 10.66.0.3. Its proxy reaches 10.66.0.2:8080.
cfrs net proxy --switch unix:/tmp/sw.sock --address 10.66.0.3 \
    --listen unix:/tmp/b.socks
```

Shim programs can also use the switch:

* `--control NAME` serves the control socket `\0NAME`. Start the program with
  `CFRSNET_CONTROL=NAME`. When the program binds a virtual address, the shim
  sends `RegisterBind`. The stack then listens on that address and sends each
  connection from the switch to the program.
* `--import VIRT` binds the abstract name of the remote address `VIRT` on this
  host. A shim program that connects to `VIRT` goes through the stack and the
  switch.
* These sockets take the same user only. The control socket has
  `SO_PASSCRED` and drops a datagram of another user. `--import` closes a
  client of another user. The stack does not send a connection to an
  abstract name that a process of another user holds. The unix listener of
  `cfrs net switch` closes a peer of another user (also root).

### 5.4 Faults

`cfrs net proxy --switch ... --address ...` takes `--drop`, `--duplicate` and
`--reorder` (probabilities from 0.0 to 1.0) and `--seed`. They put faults on
the packets that this stack sends to the switch; the switch itself
(`cfrs net switch`) has no faults. The same seed gives the same faults. With
no `--switch`, the flags are a usage error (exit 64), as a value out of 0.0
to 1.0 is. In code, use `vnet::switch::Faults` and `FaultInjector`.

```sh
cfrs net switch --listen unix:/tmp/sw.sock &
cfrs net proxy --switch unix:/tmp/sw.sock --address 10.66.0.3 --drop 0.1 --seed 7
```

## 6. Resolver, policy and capture

* `vnet::dns::Resolver` answers A and AAAA queries for a name table at
  `10.66.0.1:53`. It can send unknown names to an upstream, or answer all
  unknown names with one address.
* `vnet::policy::Acl` has allow and deny rules for addresses and ports. The
  stack applies them when a program binds or connects.
* `vnet::record` writes the link packets to a pcap file. No `CAP_NET_RAW` is
  necessary. `Replayer` sends a capture into a stack again.

## 7. Control protocol

The shim sends control messages as datagrams to `\0<CFRSNET_CONTROL>`:

```text
u8 op | u16 length | payload
```

| Op | Message | Payload |
| --- | --- | --- |
| 1 | `RegisterBind` | `u32 id`, address |
| 2 | `RegisterConnect` | `u32 id`, address |
| 3 | `Unregister` | `u32 id` |
| 4 | `Datagram` | `u32 id`, from, to, data |

An address is `u8 family` (4 or 6), the address bytes and a `u16` port.
`ControlDecoder` finds the next frame after a bad frame and counts the dropped
bytes.

## 8. Verification

* `tests/af_inet_kernel.rs` reads the socket inode from `/proc/self/fd/N` and
  checks that the kernel lists the socket in `/proc/net/unix`, not in
  `/proc/net/tcp`. It does not use `getsockname`, because the shim answers that
  call.
* `tests/shim_no_socket.rs` checks programs that never open a socket.
* `vnet::switch` tests send 64 KiB through a switch with 10% drop, 5%
  duplicates and 5% reorder, and check that the bytes arrive in order.
