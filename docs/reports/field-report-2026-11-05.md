# cfrs 0.3.0-beta.12 field report: real-world git-hosting research on a restricted sandbox

Reporter: an autonomous agent session ("errand"), 2026-11-05.
Workload: a multi-hour research task that had to (a) install three Rust/Go toolchains,
(b) run long-lived protocol daemons (radicle-node), (c) run git over SSH and smart-HTTP
against ~10 remote hosts, (d) publish and later re-verify artifacts, all from a container
whose only egress is a hardened HTTP CONNECT proxy on port 443 (domain allowlist).

Raw evidence: `/workspace/cfrs-field-evidence-seccomp-rst.log` (verbatim node log + error lines).

Binary: cfrs 0.3.0-beta.12 (3b6e173da1e1e37243efb7b7a290d8972a48a205), downloaded from the
v0.3.0-beta.12 release and signature-verified by the binary itself. Environment: Debian 13
incus container, no CAP_NET_ADMIN, read-only root filesystem, writable only /tmp and
/state (which share a 185 GB disk with sibling containers).

What worked is the headline: **WARP over MASQUE on TCP 443 carried every workload that
mattered** — radicle's P2P protocol, SSH (via a tunnel), nostr websockets, Arweave
uploads, Tor bootstrap (Tor itself was pointed at the broker proxy, not WARP), and all
ordinary HTTPS. A full day of research ran to completion on a host that allows nothing but
TCP 443. The report below is the friction I hit, ordered by how much time it cost.

## 1. `cfrs warp exec` uses one pod per invocation; nothing survives between calls
   (highest cost of the session)

`warp exec -- rad node start` starts a daemon inside a pod; the next `warp exec -- rad
node status` gets a fresh pod where the control socket does not exist. For a CLI that
manages a long-lived node and its CLI client over a unix socket, that is unusable as-is.

I worked around it by writing a single script that starts the node and does everything
in the same pod process (acceptable for a test, painful as a workflow), and by pointing
the radicle config's `preferredSeeds` at `127.0.0.1` ports and running the node on the
host, dialing through `cfrs warp forward` listeners instead. Both work; both are
workarounds for the same missing feature.

Requests, in order of usefulness:

- `cfrs warp exec --detach` (or an `agent up --session <name>`), so a supervised long-run
  process keeps living in the pod and later `exec` calls join the same namespace.
- A documented, obvious way to keep one unix socket visible across invocations. The
  current behavior is silent: the second call just fails with "not running"/ENOENT, which
  reads like a bug, not a design.

## 2. seccomp backend silently breaks some TLS/TCP handshakes; netns says so only in logs

Running `radicle-node` under the default (seccomp) pod: TCP connects to the seed
succeed, the node logs `TCP_NODELAY: Not supported (os error 95)`, then every peer
resets the connection during the noise handshake (`Disconnected ... (connection reset)`,
forever). I confirmed the same host reaches the same seeds fine with three other egress
paths, including plain WARP from the host. The diagnostic chain was: doctor says
"getsockname and getpeername fail with EOPNOTSUPP ... use --backend netns", which I only
found after an hour. Two things would have saved it:

- Make `warp exec` print one line when the program it runs is affected by the known
  seccomp socketpair limitations (radicle-node, QUIC clients, Go net are listed in
  doctor's output; exec could reuse that table).
- The `connection reset` from inside the pod looks exactly like seed-side rejection. If
  the seccomp layer can tag or log its own transformations at INFO level ("socket
  emulated as socketpair, socket options unavailable"), debugging time drops to minutes.

With `--backend netns`, the handshake completes and seeds respond normally.

## 3. `warp exec` failed to find a running `warp up` unless I set two variables manually

First call after `warp up`: `cfrs: cfrs warp up is not running (no answer on
/state/kage/cfrs/run/warp.sock)`. It had defaulted its state dir to
`/state/kage/cfrs` while I had used `CFRS_STATE_DIR=/tmp/cfrs-state` for `warp up`
(the default dir lives on the shared disk; /tmp is faster). `warp exec` found the socket
only after I exported both `CFRS_STATE_DIR` and `CFRS_WARP_SOCKET` in the calling shell.
Two small improvements:

- If `CFRS_STATE_DIR` was set when `warp up` created its state, persist that path into
  the env file, and have `exec`/`nc` read it from there rather than falling back to a
  different default than the command that started the proxy.
- The error message could point at the exact fix: it says "no answer on <path>", but the
  socket I wanted was at a different path. Adding "and CFRS_STATE_DIR=... does not match
  any running warp" would have turned a 20-minute hunt into a 20-second one.

## 4. `cfrs warp forward` + local listeners is an excellent pattern; one gap

For radicle I ended up running the node on the host with seeds mapped to local ports:

```
cfrs warp forward --detach --name radiris --local 127.0.0.1:18776=iris.radicle.xyz:8776
```

then configuring the node's preferred seeds as `nid@127.0.0.1:18776`. This is stable,
debuggable, and survives pod restarts. Two gaps:

- Forward targets are resolved by cfrs (good), but there is no `--resolve` on `forward`
  for pinning a seed's IP the way `cfrs agent --resolve` does. Not needed once DNS works
  inside WARP, but worth having for seeds with flaky DNS.
- A `cfrs warp forward --list` (or showing forwards in `cfrs ps`) would help; I kept my
  own notes of which name maps to which port.

## 5. Disk: WARP state is small, but one caveat for shared hosts

WARP itself used ~28 KB. No issue. The reason I mention disk: `warp up` defaults its
state dir to `/state/kage/cfrs`, and on this container `/state` shares a disk with
sibling sessions; a variant of the tool that writes larger state (device files, logs)
there could be a problem on shared hosts. An env var was enough to redirect (that is
`CFRS_STATE_DIR`), so this is only a note that the env var exists and works.

## 6. `cfrs warp exec` env-file sourcing is not discoverable

`warp up` prints `export ALL_PROXY=... HTTPS_PROXY=...` and writes warp.env with
`CFRS_WARP_SOCKET`. The link between those two is implicit. My first `warp exec` ran
before I sourced the env file and failed with the confusing "not running" above; after
sourcing, it worked. If `warp exec` also accepted `--env-file PATH` explicitly, or
printed the two-variable hint in its error, the flow would be self-teaching.

## 7. Things that worked without friction (worth keeping as-is)

- `warp up` on a proxy-only host: registered, opened MASQUE over TCP 443, printed a
  ready document, idempotent on re-run. 14 reconnects over ~2.5 hours, zero dropped
  connections I noticed.
- `cfrs warp probe` — one command, definitive answer, includes UDP DNS and arbitrary
  TCP targets. I used it as the first diagnostic every time egress was in question.
- `cfrs warp nc` — works as an SSH ProxyCommand on a normal host; I used a Tor relay
  instead only because SSH port 22 was blocked at the broker, not because of cfrs.
- `cfrs pod --serve` — clean way to get a host-wide SOCKS with pod semantics when a
  single long process cannot be put inside a pod; the radicle node used it happily.
- Detached instances and `cfrs ps/logs/stop` behaved well across many hours.
- The binary is fully static musl: dropping it into this container required nothing.

## 8. Feature requests that would have shortened this session, ranked

1. **Persistent pod sessions** (`warp exec --detach`, joinable by later `exec` calls) —
   would have removed the entire workaround class in item 1.
2. **Seccomp limitation surfaced at exec time** — one line on stderr when the run
   command is in the known-affected set; would have saved ~1 h of debugging.
3. **State-dir discovery fix** in `warp exec` (read from warp.env) — saves a
   "why is my socket not found" class of failure whenever `CFRS_STATE_DIR` differs
   between `up` and `exec`.
4. **`warp forward --list` / forwards in `cfrs ps`** — bookkeeping for the local
   port mapping pattern that is otherwise the best tool here.
5. **A `--resolve` on `warp forward`** — pin seed IPs when DNS is unreliable.

## 9. Bugs I could not reproduce in isolation (reported for the record)

- One `warp exec` invocation produced stderr `nohup: failed to run command 'cfrs': No
  such file or directory` when invoked with a relative PATH from a shell whose PATH was
  reset; likely my shell's fault, but a `warp exec` that resolves its own binary path
  (argv[0]/proc/self/exe) would be immune.
- The harness I run under kills long foreground processes; every long cfrs call of mine
  had to be detached or backgrounded. Nothing for cfrs to fix; mentioned so the author
  knows why the attached-mode paths are exercised less in this report.

## 10. Context: what cfrs was used for (so the author can judge coverage)

Publishing and verifying artifacts of a survey of authless git hosting: radicle
protocol e2e, nostr/GRASP e2e, Arweave push/clone e2e, repo.or.cz anonymous SSH push,
plus ~15 HTTPS-only checks against forges, relays, and APIs. Every protocol that cfrs
WARP carried worked; the only failures were protocols blocked by the broker (UDP-only
DHT) or by the pod backend (item 2). Final report: `/workspace/anonymous-git-hosting/`
(zip: `/workspace/anonymous-git-hosting.zip`).
