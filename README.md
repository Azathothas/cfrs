# cfrs

`cfrs` is one Rust binary that does the work of three tools:

| Tool | `cfrs` command |
| --- | --- |
| `cloudflared` quick tunnels and named tunnels | `cfrs tunnel`, `cfrs serve`, `cfrs share`, `cfrs connect` |
| Try Cloudflare (`*.trycloudflare.com`) | `cfrs tunnel` with no account. A quick tunnel is for tests and development: no uptime guarantee, at most 200 requests in flight (more get `429`), no Server-Sent Events, and the Cloudflare Online Services Terms ([limits and terms](https://github.com/Azathothas/cfrs/blob/main/docs/protocol.md#7-limits-of-quick-tunnels)) |
| The Cloudflare WARP client | `cfrs warp` |

`cfrs` is made for hosts with strong limits. The table gives each limit, the
part of `cfrs` for it, and where that part is tested.

| Limit on the host | Part of `cfrs` | Tested |
| --- | --- | --- |
| No UDP to the edge | HTTP/2 edge leg on TCP 7844 | CI, live against the Cloudflare edge |
| Only TCP 443 out | QUIC edge leg inside WARP (MASQUE) | CI, live |
| No DNS resolver | DNS over HTTPS by IP address (1.1.1.1, 8.8.8.8), then a static edge list | CI and a sandbox with an HTTP proxy |
| Egress through a proxy only | HTTP `CONNECT`, SOCKS5 and `NO_PROXY` for each connection | `tests/egress.rs` |
| No root, no TUN, no network namespace | `cfrs pod` (seccomp backend), `cfrs warp run` | CI and a sandbox |
| No `AF_INET` bind | `cfrs net` (shim and userspace stack), unix-socket origins | CI and a sandbox |

The live workflow (`.github/workflows/live.yml`, on each push and each day) runs `cfrs demo` with
each edge leg on a GitHub runner and fetches the public URL. One limit stays:
a proxy that terminates TLS cannot carry the edge connection or the MASQUE
connection, because both need the Cloudflare certificate chain (and MASQUE
needs a client certificate).

The repository is a Cargo workspace:

| Crate | Contents |
| --- | --- |
| `cfrs` (root) | The CLI and the library: the edge client (provisioning, discovery, QUIC, HTTP/2, Cap'n Proto and its RPC), the service layer, WARP, the virtual network. |
| `crates/pod-netns` | A library and a CLI: run a program with all its traffic sent through a proxy. |

## Install

### Release binaries

Each [release](https://github.com/Azathothas/cfrs/releases) has static
Linux binaries of `cfrs` and `pod-netns` for `x86_64`, `aarch64`, `armv7`,
`riscv64gc`, `i686`, `arm` (ARMv6, hard float), `loongarch64` and
`powerpc64le` (from v0.3.0-beta.2 on; v0.3.0-beta.1 has `x86_64`,
`aarch64`, `armv7` and `riscv64gc`, and no `cfrs.1`). cfrs is for Linux
only. This README describes `main`; the notes in `docs/releases/` say what
a tag has. Each release also has these files:

| File | Contents |
| --- | --- |
| `SHA256SUMS` | The SHA-256 of each binary and of `cfrs.1`. |
| `SHA256SUMS.sigstore.json` | The keyless cosign signature of `SHA256SUMS`. |
| `provenance.sigstore.json` | The SLSA provenance of the binaries. |
| `cfrs.1` | The manual page (`cfrs man --roff`). |
| `THIRD-PARTY-LICENSES.md` | The license texts of the crates in the binaries. |

Verify the files before you use them. Download the binary, `SHA256SUMS` and
the two bundles to one directory. Then do these steps:

1. Check the checksums. The command ignores the files that you did not
   download:

   ```sh
   sha256sum -c --ignore-missing SHA256SUMS
   ```

2. Check the signature of `SHA256SUMS`. Replace `vX.Y.Z` with the tag:

   ```sh
   cosign verify-blob --bundle SHA256SUMS.sigstore.json \
     --certificate-identity https://github.com/Azathothas/cfrs/.github/workflows/release.yml@refs/tags/vX.Y.Z \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
   ```

3. Check the provenance of the binary (gh 2.49 or later):

   ```sh
   gh attestation verify cfrs-x86_64-unknown-linux-musl --repo Azathothas/cfrs \
     --signer-workflow Azathothas/cfrs/.github/workflows/release.yml
   ```

   With no network access to the GitHub API, give the bundle and a trusted
   root. Make `trusted_root.jsonl` on a host with network access
   (`gh attestation trusted-root > trusted_root.jsonl`), and copy it:

   ```sh
   gh attestation verify cfrs-x86_64-unknown-linux-musl --repo Azathothas/cfrs \
     --signer-workflow Azathothas/cfrs/.github/workflows/release.yml \
     --bundle provenance.sigstore.json --custom-trusted-root trusted_root.jsonl
   ```

A binary that has one changed byte fails each check. The workflow
`.github/workflows/release-proofs.yml` does these checks on a fresh runner
after each release. It also does each check on a changed copy, which must
fail.

### Install script

`scripts/install.sh` installs the binary of the newest release
(prereleases too) for this machine. It is POSIX `sh`:

```sh
s=$(curl -fsSL https://raw.githubusercontent.com/Azathothas/cfrs/main/scripts/install.sh) && sh -c "$s"
```

With wget: `s=$(wget -qO- URL) && sh -c "$s"`. Do not use `curl URL | sh`
in a script or a CI step: a pipe has the exit status of `sh`, and `sh`
exits 0 when `curl` fails or is missing.

* It uses the first downloader that it finds: `curl`, `wget`, `aria2c`,
  `http` (HTTPie), `python3`, `python` or `perl` (`HTTP::Tiny` with TLS),
  and last `busybox wget` (also a `wget` that is the busybox applet: it
  goes after `python3`, `python` and `perl`).
  HTTPS only; redirects to plain HTTP are refused. busybox wget does not
  check TLS certificates: the script says so in a warning, and with no
  `cosign` the check of `SHA256SUMS` then does not protect the download. A
  busybox with no TLS (no `ssl_client`) is not used.
* It checks the binary against `SHA256SUMS` (`sha256sum`, `shasum`,
  `openssl`, `busybox` or `python3`), and the cosign signature of
  `SHA256SUMS` when `cosign` is installed. A failed check stops it, and
  cosign then shows its output.
* It runs the new binary (`--version`) in the install directory before it
  replaces the old binary. A binary that does not run on this machine, or
  that does not print `cfrs VERSION` of the release, does not replace the
  old one. The copy is a new file from `mktemp` with mode 0755 (also with
  a restrictive umask). When the path of the binary is a directory or
  another file that is not a regular file, the script stops before the
  downloads.
* The directory: `CFRS_INSTALL_DIR`, else `/usr/local/bin` for root, else
  `$XDG_BIN_HOME`, else `~/.local/bin`. A line says how to add it to `PATH`.
  The script checks the directory before the downloads.
* `CFRS_VERSION=<TAG>` (for example `v0.3.0-beta.11`) installs that release, with no request to
  the GitHub API. For the newest release, the script reads the API; when
  the API refuses (403 on a shared address), it reads `releases.atom`.
  A draft release is not used.
  `GITHUB_TOKEN` or `GH_TOKEN` goes to `api.github.com` only. The token is
  not in the trace of `DEBUG=1` and not in the arguments of the downloader:
  curl reads it from stdin, wget from a private file.
* `CFRS_POD_NETNS=1` also installs `pod-netns`. `CFRS_DOWNLOADER=wget`
  selects the downloader.
* A missing file of the release, an empty download and a failed download
  have different messages. INT, TERM and HUP stop the script and remove its files.

### Ephemeral hosts

A hosted notebook, a rebuilt container or a CI job can lose its disk at
each start. Then three things go:

* The binary: give `CFRS_INSTALL_DIR` a directory that stays.
* The WARP device: give `CFRS_STATE_DIR` (or `--identity PATH`) a directory
  that stays. Without it, each start registers a new anonymous device (the
  service limits new devices; see "WARP"). `CFRS_STATE_DIR=none` uses a new
  device on purpose.
* The release list: a pinned `CFRS_VERSION` uses no GitHub API.

This cell (Python 3, no curl) installs cfrs in `KEEP`. The same cell is in
`notebooks/install.ipynb`. It fails when the install fails (`check=True`):

```python
# Install cfrs on a host that loses its disk at each start (a notebook).
# KEEP is a directory that stays, for example a mounted drive.
import os
import subprocess
import urllib.request

KEEP = os.environ.get("CFRS_KEEP", os.path.expanduser("~/cfrs-keep"))
VERSION = "latest"  # A tag (for example v0.3.0-beta.11) uses no GitHub API.
URL = "https://raw.githubusercontent.com/Azathothas/cfrs/main/scripts/install.sh"

os.makedirs(os.path.join(KEEP, "bin"), exist_ok=True)
script = os.path.join(KEEP, "install.sh")
with open(script, "wb") as f:
    f.write(urllib.request.urlopen(URL, timeout=60).read())
env = dict(os.environ, CFRS_INSTALL_DIR=os.path.join(KEEP, "bin"), CFRS_VERSION=VERSION)
subprocess.run(["sh", script], env=env, check=True)

# The binary and the WARP device stay in KEEP.
os.environ["PATH"] = os.path.join(KEEP, "bin") + ":" + os.environ["PATH"]
os.environ["CFRS_STATE_DIR"] = os.path.join(KEEP, "state")
print(subprocess.run(["cfrs", "--version"], check=True, capture_output=True, text=True).stdout)
```

### Container image

Each release has an image for each Linux architecture of the binaries:
`ghcr.io/azathothas/cfrs:<tag>` (a manifest list), `:<tag>-<arch>` for one
architecture (`amd64`, `arm64`, `armv7`, `armv6`, `386`, `riscv64`,
`ppc64le`, `loong64`), and `:beta` for the newest prerelease. `:latest` is
for the newest release that is not a prerelease; none exists yet, so
`:latest` has no image. The image is `FROM scratch` with `cfrs`
and `pod-netns` in `/usr/local/bin`. It runs as user 65534. The state
directory is the volume `/var/lib/cfrs` (`CFRS_STATE_DIR`). The entry point
is `cfrs`. In the container, cfrs is PID 1 (no init): SIGTERM and SIGINT
stop it at each stage, also before the ready line (exit 143 and 130).

```sh
docker run --rm ghcr.io/azathothas/cfrs:beta --version
docker run -d --name warp -v cfrs-state:/var/lib/cfrs -p 127.0.0.1:40000:40000 \
    ghcr.io/azathothas/cfrs:beta warp proxy --listen tcp://0.0.0.0:40000
docker run --rm ghcr.io/azathothas/cfrs:beta demo --exit-on-verify
```

The proxy listens on all addresses of the container: publish the port on
127.0.0.1 only, or give `--proxy-user` and `--proxy-password-file`.

## Quick start

```sh
# Make a quick tunnel to a local HTTP server.
cfrs tunnel --url http://127.0.0.1:8080

# Make a quick tunnel to an HTTP server on a unix socket.
cfrs tunnel --unix /run/app.sock

# Test the full path: a built-in origin, a tunnel, a fetch of the public URL.
cfrs demo --exit-on-verify
```

## Update

```sh
cfrs update --check              # say whether a newer release exists
cfrs update                      # install it
cfrs update --version <TAG>      # install the release <TAG>
cfrs update --rollback           # put the binary before the update back
```

`cfrs update` installs a release only after these checks: the certificate
of `SHA256SUMS.sigstore.json` chains to the Fulcio roots of Sigstore and
names `release.yml` of this repository at the tag, the signature over
`SHA256SUMS` is valid, the SHA-256 of the binary is its line in
`SHA256SUMS`, and the new binary runs `--version` in 10 seconds, with no
stdin, exits 0 and prints the version of the tag. After the run, the file
must still be the same file (device and inode), a regular file of this
user that other users cannot write; else cfrs stops. Then the binary before
is kept as `cfrs.prev` beside it, and a rename puts the new binary (mode
0755, also with a restrictive umask) in place. `cfrs update --rollback` puts `cfrs.prev` back (it must pass the
same run first) and keeps the binary that was in place as `cfrs.prev`;
it uses no network. cfrs does not check the inclusion proof of the Rekor
log. A prerelease is
installed only with `--version`, or when the current binary is a
prerelease.

* `--version TAG` uses no request to the GitHub API: the URLs of the files
  follow from the tag. A tag with no release exits 69 ("no release has the
  tag"). A text that is not a tag (a `/`, a `..`, a character other than
  `0-9 A-Z a-z . + -`) exits 64. cfrs skips such a tag in the API and in
  `releases.atom` too.
* With no `--version`, cfrs reads the GitHub API, else `releases.atom` (the
  API answers 403 on a shared address; the feed has no quota).
* `--version` of the installed version says so and exits 0; `--force`
  installs it again. `--force` with no `--version` installs the newest
  release also when it is the installed version; it does not go back to
  an older release.
* The repository is fixed (it names the signer of the binary). cfrs does
  not read `CFRS_REPO` (a variable of `scripts/install.sh`); a warning says
  so.

## Tunnels

### Origins

```sh
cfrs tunnel --url http://127.0.0.1:8080   # HTTP or HTTPS origin
cfrs tunnel --port 8080                   # the same as http://127.0.0.1:8080
cfrs tunnel --unix /run/app.sock          # HTTP origin on a unix socket
cfrs tunnel --hello-world                 # built-in test origin
cfrs tunnel --config ./config.yml         # cloudflared ingress rules
cfrs tunnel --token "$T" --tcp 10.0.0.5:5432  # raw TCP origin (named tunnel)
```

A raw TCP origin (`--tcp host:port` or `tcp://host:port`) carries TCP and
WebSocket streams of a named tunnel (WARP routing, `cloudflared access
tcp`). A quick tunnel receives HTTP: cfrs answers each HTTP request to a
raw TCP origin with 501, and does not verify the public URL. For TCP
through a quick tunnel, use `--forward` and `cfrs connect` (see "Raw
streams through a quick tunnel").

The service strings are the same as in cloudflared:

```text
http://host:port     https://host:port     unix:/path/to.sock
unix+tls:/path.sock  tcp://host:port       http_status:404
hello_world          metrics               static:/srv/www
spa:/srv/www
```

* `static:` serves a directory.
* `spa:` serves a directory and sends `index.html` for unknown paths.
* `metrics` serves the Prometheus metrics of the tunnel.
  `cfrs_decisions_total{decision,outcome}` counts the path decisions of
  the process: `dns` (`ip`, `pin`, `system`, `doh`, `fail`), `egress`
  (`direct`, `none`, `no_proxy`, `via`, `http`, `socks5`, `unix`, `exec`),
  `leg` (the leg that won), `masque` (`direct`, `relay`, `relay_first`,
  `no_relay`), `dispatch` (the requests of `warp proxy`) and `rule`. The
  health line of `warp proxy` has the same counters.
* `--http-host-header NAME` sets the `Host` header for the origin.
* `--no-tls-verify` does not verify the TLS certificate of an HTTPS origin.

All built-in origins run in the process. They do not open a TCP listener.

### Configuration file

`cfrs tunnel --config` reads a cloudflared YAML file:

```yaml
tunnel: my-tunnel                      # the name or the UUID of the tunnel
credentials-file: /etc/cfrs/creds.json
ha-connections: 2
protocol: auto
ingress:
  - hostname: app.example.com
    path: /api
    service: http://127.0.0.1:8080
    originRequest:
      noTLSVerify: true
      connectTimeout: 5s
  - service: http_status:404
```

* The last rule must match all requests (no `hostname`, no `path`). cfrs
  refuses a file where it does not.
* `path:` is a literal prefix of the request path in cfrs. cloudflared
  reads it as a regular expression. A `path:` with a character of a
  regular expression (`^ $ * + ? ( ) [ ] { } | \`) is an error (exit 78):
  write the prefix, for example `path: /api/`.
* With no `ingress:`, `url:` gives one rule for each request (the same
  services as `service:`), and `hello-world: true` gives the hello-world
  page. `url:` or `hello-world:` with `ingress:` is an error.
* A file with no rule (no `ingress:`, `url:` or `hello-world:`) fails
  `--check` (exit 78) and the run.
* With `credentials-file:`, `tunnel:` is the name or the UUID of the tunnel,
  as in cloudflared. A UUID must be the `TunnelID` of the file. With
  `tunnel:` only, it is a tunnel token.
* `token:` is the tunnel token of a named tunnel. `token:` with
  `credentials-file:` is an error. With `token:`, a `tunnel:` must be the
  tunnel id of the token.
* With no `tunnel:`, no `credentials-file:` and no `token:`, cfrs starts a
  quick tunnel. `--token`, `TUNNEL_TOKEN` and `--credentials-file` win over
  the file.
* cfrs ignores the cloudflared keys that it does not use (`metrics`,
  `loglevel`, `warp-routing`, `tcpKeepAlive`, ...). Another key is an error
  (exit 78), with the nearest key. cfrs checks the keys at the top level, in
  each ingress rule and in each `originRequest`.
* The top-level `originRequest` is the default of each rule. A key of the
  rule wins.
* `protocol:` and `ha-connections:` of the file are used. A flag
  (`--protocol`, `--ha-connections`) wins over the file.
* `--token` and `--credentials-file` on one command line are a usage error
  (exit 64). With the token from `TUNNEL_TOKEN`, `--credentials-file` wins,
  and a warning says so. A bad token or credentials file exits 78.
* A UTF-8 BOM at the start of the file is skipped. A list, an empty file, a
  rule with no `service`, a time with no unit (`connectTimeout: 5`) and a
  value of the wrong type each have their own message.

cfrs reads the YAML with its own reader (`src/yaml.rs`). The reader accepts
block mappings, block sequences, plain and quoted scalars on one line, and
comments. It refuses anchors, aliases, tags, block scalars (`|`, `>`), flow
collections that are not empty, tabs in the indentation, duplicate keys and
a document that nests deeper than 64 levels, and gives the line number.

### Named tunnels

A named tunnel uses a Cloudflare account and a hostname from the dashboard.

```sh
TUNNEL_TOKEN=<token> cfrs tunnel --url http://127.0.0.1:8080
cfrs tunnel --token-file /run/secrets/tunnel-token --url http://127.0.0.1:8080
cfrs tunnel --credentials-file ~/.cloudflared/<id>.json --url http://127.0.0.1:8080
```

`--token <token>` also works. Other users of the host can read a command
line, so `TUNNEL_TOKEN` or a file is safer. `--token-file PATH` (or
`TUNNEL_TOKEN_FILE`) reads the token from a file; white space at the ends
is removed. `cfrs relay connect --token-file PATH` reads a connect token,
and `cfrs warp license -` reads the license key from stdin.

A command line of cloudflared works for a tunnel: `cfrs tunnel run --token
T` is `cfrs tunnel --token T`, `--no-autoupdate` is ignored, and
`--loglevel debug|info|warn|error` becomes `-v`, nothing or `-q`. Another
flag of cloudflared (`--logfile`, `--pidfile`, `--metrics`, ...) is a usage
error with the step to take in cfrs.

### Edge protocol and transport

`--protocol` selects the protocol to the edge. `--transport` selects the
path.

| Leg | Socket on the host | Use it when |
| --- | --- | --- |
| `quic` | UDP 7844 | UDP to the edge is open. This is the fastest leg. |
| `http2` | TCP 7844, directly or through the proxy | UDP is blocked and TCP 7844 is open. |
| `quic+warp` | TCP 443 only (MASQUE) | Only TCP 443 is open. |
| `http2+relay` | TCP 443 to a WebSocket relay | Only TCP 443 is open, and WARP does not work (the proxy terminates TLS or takes names only). Only with `--transport relay`. |

With the default values (`--protocol auto --transport auto`), `cfrs` tries the
legs in the order of the table, in a staggered race: the next leg starts when
the leg before has not registered in 2 seconds, or at once when it fails, and
the first leg that registers stays (`docs/protocol.md` section 3.3).
`--leg-failover serial` waits for each failure (8 seconds at most for each
attempt). Other values:

| `--protocol` | `--transport` | Legs |
| --- | --- | --- |
| `auto` | `auto` | `quic`, `http2`, `quic+warp` |
| `quic` | `auto` | `quic`, `quic+warp` |
| `http2` | `auto` or `direct` | `http2` |
| `auto` | `direct` | `quic`, `http2` |
| `quic` | `direct` | `quic` |
| `auto` or `quic` | `warp` | `quic+warp` |
| `auto` or `http2` | `relay` | `http2+relay` |

`h2` is a name of `http2`. With a proxy, `auto` drops `quic` (see "Proxies
and DNS"); an explicit `--protocol quic` keeps it, and a warning says that
QUIC goes around the proxy.

`--transport relay` sends the HTTP/2 leg in a WebSocket to a
WebSocket-to-TCP relay on TCP 443 (`--relay URL`, or `CFRS_RELAY`; the
default is `https://tcp.ssh.relay.ajam.dev`). The relay opens TCP to the
edge on port 7844. The TLS to the edge is in the WebSocket, so the relay
does not see the tunnel. `CFRS_RELAY_TOKEN` gives a relay token; without
it, `cfrs` mints one and keeps it in the state directory. When the relay
host does not answer, `cfrs` tries other hosts of the same deployment (a
comma list in `--relay`, else the pool of the relay). The relay carries IPv4 TCP only, and it ends a
session after 64 MiB or 12 hours. Before that (at 60 MiB or 11.5 hours),
the tunnel connects a replacement edge connection, and the old one
finishes its open streams (`docs/protocol.md` section 3.4). A WARP
(MASQUE) session through the relay is replaced at the same limits: a new
session takes the new connections, and the open connections go on in the
old session for 90 s.

`--warp-identity PATH` keeps the WARP device in a file. Without it, each run
registers a new anonymous device. `CFRS_EDGE=ip:port,...` replaces edge
discovery.

### Serve a directory

```sh
cfrs serve --dir ./public
cfrs serve --dir ./app --spa          # send index.html for unknown paths
```

`cfrs serve` serves only the files in `--dir`:

* A symlink is served only when its real path is in `--dir`.
* A name that starts with a dot (`.git`, `.env`) is not served.
* Only regular files and directories are served (no FIFO, socket or
  device).

Each other path answers 404. With `--spa`, an unknown path answers the
`index.html` with status 200.

The library type `cfrs::origin::StaticDir` has the same rules. It also
applies them to the directory index and to the SPA index.

### Share files

```sh
cfrs share --mode upload --password                 # receive files, with a PIN
cfrs share --mode download --file ./report.pdf      # send one file
cfrs share --mode proxy --port 3000                 # share a local port, with a PIN
cfrs share --mode proxy --unix /run/api.sock        # share an HTTP unix socket, with a PIN
cfrs share --mode upload --dir /tmp/inbox --stop-after --idle-secs 600
```

* Give a mode: `--mode upload` (or `--dir DIR`), `--file FILE`, `--port
  PORT` or `--unix PATH`. A bare `cfrs share` is a usage error (exit 64),
  and opens no session. With `--mode upload` and no `--dir`, the files go
  to `~/Downloads/cfrs` (or `~/cfrs-uploads` when `~/Downloads` does not
  exist).
* The public path is `/s/<token>/`. The token has 32 random bytes, and a
  path with another token answers 404.
* `--password` adds a 6-digit PIN. The host shows the PIN. The PIN check uses
  a constant-time compare. After 10 wrong codes, no code opens the session:
  start a new one. Requests at the same time get at most 10 compares in
  total. A correct code sets the count of wrong codes to 0. After the
  unlock, the browser goes back to a path of the same site only.
* The unlock cookie has `HttpOnly`, `Secure` and `SameSite=Lax`: open the
  session with `https://` (a browser does not keep a `Secure` cookie of
  plain http). An unlock POST from another site (`Sec-Fetch-Site`, or an
  `Origin` that is not the host) gets 403 and uses no try. A client that
  knows the URL can still use the 10 tries: the edge does not give cfrs
  the address of the visitor, so the limit is for the session, not for
  each visitor.
* A locked GET or HEAD gets the PIN page with 200 (for a browser). A locked
  request with another method (an upload POST, an API call) gets the page
  with 403, and nothing is done. A wrong PIN gets 403.
* The upload limits are 512 MiB for each file, 32 files and 4 GiB in total
  for each session. A request over a limit gets 413, and no file of that
  request is saved: each file waits in a hidden `.part` file until the
  request ends. A body with no data for 60 s gets 408 and leaves no file.
* An uploaded file has mode 0600 (only the user of cfrs can read it),
  with each umask.
* One upload request holds at most `--max-request` bytes (default
  100000000, the limit of the Cloudflare edge for one request body). Each
  field of the request counts, also a field with no file. A
  larger `Content-Length` gets 413 and saves nothing: cfrs reads the body
  and drops it first (until its end, a pause of 5 s, or 120 s), because an
  answer before the end of the upload does not reach the visitor reliably
  through the edge. The page refuses such a selection before it sends. To
  send more, use more uploads.
* A download name that is not ASCII goes in `filename*=UTF-8''...` (RFC
  5987), with an ASCII `filename=`.
* `--stop-after` stops the session after the first transfer. `--idle-secs`
  stops it after a time with no activity. The idle clock starts when the
  session serves, not before the provisioning.
* Each reply of a share session has `Cache-Control: no-store`. In proxy
  mode, the replies of the local server keep their own headers.
* A download answers `If-None-Match: *` and a weak tag (`W/"..."`) with
  304.

### A credential in front of a tunnel

```sh
umask 077; printf '%s\n' 'a long password' > ~/.cfrs-pass
cfrs tunnel --port 3000 --auth-user me --auth-password-file ~/.cfrs-pass
curl -u me:'a long password' https://<random>.trycloudflare.com/
```

* `--auth-user USER` and `--auth-password-file FILE` (`CFRS_AUTH_USER`,
  `CFRS_AUTH_PASSWORD_FILE`) work with `tunnel`, `serve`, `share` and
  `demo`. Each request must give the user and the password (HTTP Basic).
  Else cfrs answers 401 with `WWW-Authenticate: Basic realm="cfrs"`, and
  the request reaches no origin. The origin does not get the
  `Authorization` header.
* The file has the password on its first line and mode 0600; else exit 78.
  The password is not on the command line.
* The check covers the HTTP origins and the `--forward` endpoint:
  `cfrs connect --auth-user USER --auth-password-file FILE` sends the
  credential in the WebSocket upgrade. A raw `--tcp` origin carries no HTTP
  header: `--auth-user` with `--tcp` is a usage error (exit 64).
* The verify of the public URL takes the 401 as the normal answer.
* Basic goes in the TLS to the edge of Cloudflare: Cloudflare can see it.
  The credential does not hide the URL.

### Raw streams through a quick tunnel

A quick tunnel carries HTTP and WebSocket. `--forward` puts a WebSocket
endpoint at `/__cfrs/ws`. `cfrs connect` changes local sockets into
connections through that endpoint. Thus SSH, databases and unix sockets can
go through a quick tunnel.

```sh
# Server: expose a unix socket (or tcp://host:port).
cfrs tunnel --forward unix:/run/app.sock

# Client: local port 8080 goes to that unix socket.
cfrs connect wss://<random>.trycloudflare.com/__cfrs/ws -L tcp://127.0.0.1:8080
```

The tunnel prints the endpoint (`cfrs: forward  wss://...`). The ready
event of `--json`, the ready document of `--detach` and `cfrs ps --json`
have it as `forward` (and `forward_path`); `cfrs ps` shows it on a second
line.

`-L` accepts `tcp://[bind:]port` and `unix:///path` and is repeatable. Each
local connection gets its own WebSocket. `--forward` and an origin can be used
together: the origin gets all paths other than `/__cfrs/ws`.

`cfrs connect` dials as the other commands do: `--proxy` (or HTTPS_PROXY and
NO_PROXY), `--resolve`, the system resolver and DoH, and the roots of
`--ca-file`. At start, it opens one WebSocket to the remote and exits 69 when
the remote does not answer; `--no-check` starts without this check. A unix
socket that another process serves is refused (exit 69); `--replace` takes
it. At the end, cfrs removes the socket files that it made. `--detach` and
`--name` work as for `tunnel` (see "Run in the background"); the ready
document has `remote`, `listen` and `listeners`. At `-v`, each WebSocket
logs the time of its TCP, TLS and upgrade steps.

### Other commands

```sh
cfrs ports            # list the listening TCP ports (Linux)
cfrs ports --probe    # only the ports that accept a connection
cfrs qr <URL>         # print a QR code
```

## WARP

`cfrs warp` is a WARP client. It uses MASQUE (`CONNECT-IP` over HTTP/2) on
TCP 443. It needs no root and no TUN device.

```sh
cfrs warp register                # register a device, or load the saved one
cfrs warp status                  # the device and the account
cfrs warp status --json           # the account record as JSON
cfrs warp license <KEY>           # attach a WARP+ license key
cfrs warp rotate                  # make and enrol a new MASQUE key
cfrs warp delete                  # remove the device and the saved file
cfrs warp probe                   # test TCP connects through the tunnel
cfrs warp exit                    # the exit colo, country, address and IPv6 address
cfrs warp scan --candidate 162.159.198.1   # measure front doors (TCP and TLS)
cfrs warp export --out warp.conf  # a WireGuard device for other clients (UDP)
cfrs warp proxy                   # local SOCKS5 and HTTP CONNECT proxy
cfrs warp forward -L 5432=db.internal:5432   # as ssh -L, through WARP
cfrs warp run -- curl https://cloudflare.com/cdn-cgi/trace
cfrs warp tun --interface cfrs0        # TUN interface (needs CAP_NET_ADMIN)
```

* The device and its key are in `warp.json` in the state directory: the
  first that cfrs can write of `CFRS_STATE_DIR`, `$XDG_STATE_HOME/cfrs`,
  `~/.local/state/cfrs`, `$XDG_RUNTIME_DIR/cfrs` and `cfrs-<uid>` in the
  temporary directory. The file mode is 0600. cfrs checks the directory
  before it registers a device. cfrs writes no file in a directory of
  another user (root with the `HOME` of a user): the state directory skips
  that `HOME`, and `warp ssh-config --write`, `warp up --persist` and
  `--env-d`, and `autostart` exit 78. `CFRS_FOREIGN_HOME=allow` writes
  anyway. Use `--identity PATH` for a different file,
  `--ephemeral` or `CFRS_STATE_DIR=none` to use a new device for one run.
* IPv6: the stack has the IPv4 and the IPv6 address of the device. The
  proxy asks for A and AAAA records through the tunnel and tries IPv4
  first, then IPv6, so a host with only AAAA records works too.
  `warp tun` adds the IPv6 address (/128) to the interface.
* What a destination sees (measured by a tester on 0.3.0-beta.8; issue
  183): not the address of the device (`172.16.0.2`, `2606:4700:110:...`),
  but an egress address of Cloudflare. The egress address stays the same
  in one MASQUE session, and a new session gets a new one (IPv6 from a
  `2a09:bac1::/32` or `2a09:bac5::/32` prefix). The `--listen` listeners of
  one proxy share one session and one address; each `--listen-identity`
  has its own device, session and address. `warp rotate` changes the
  MASQUE key only. `cdn-cgi/trace` gives the IPv4 `ip=` also for an IPv6
  flow.
* `--session-max-age SECS` (or `CFRS_WARP_SESSION_MAX_AGE`) closes each
  session at that age and opens a new one, with a new egress address, for
  `warp proxy`, `forward`, `run` and `up`. The TCP flows of the old session
  end. Default: off. The log gives the cause of each close of a session.
* New devices: the WARP service limits the registrations of each address.
  Observed: HTTP 429 (error 1015) after about 10 new devices in 90 minutes,
  cleared after about 30 minutes. cfrs then says so. A saved identity,
  `warp rotate` and new sessions do not register. `--ephemeral`, a new
  `--listen-identity` file and `warp export` each register one device.
* `cfrs warp proxy` listens on `tcp://127.0.0.1:40000` by default. Use
  `--listen unix:/path` on a host that refuses `AF_INET` binds. Each
  `--listen` is bound on its own: a listener that the host refuses is
  reported, and the proxy starts with the others (`--strict` exits 69
  instead). With no listener, the exit code is 69. Names are resolved
  through the tunnel. SOCKS5 UDP ASSOCIATE is supported.
* `--proxy-user USER --proxy-password-file FILE` (also on `warp up`): each
  client must give the user and the password of the first line of FILE
  (mode 0600), with SOCKS5 (RFC 1929) or HTTP `Proxy-Authorization: Basic`.
  A listener on an address that is not loopback, with no credentials, gets
  a warning. `--max-connections N` limits the clients; `--dns ADDR`
  answers DNS through WARP.
* `--fragment-client-hello [off|record|sni]` (default `off`; a flag of `cfrs warp`, before or after the subcommand; `CFRS_WARP_FRAGMENT`):
  the TLS ClientHello of the MASQUE connection goes in more than one record
  of `--fragment-size` bytes (16 to 4096; default 64-160). `sni` ends the first record in the
  server name. The server joins the records (RFC 8446, section 5.1); a
  middlebox that reads the name from the first record does not find it.
* `--carry wg` (a flag of `cfrs warp`, before or after the subcommand; `CFRS_WARP_CARRY`): a second WireGuard device
  (`warp-carry.json` in the state directory) inside the tunnel, on a UDP
  socket of the first stack. The tools use the stack of the second device
  (IPv4, MTU 1200), so a destination sees its exit. With `--transport
  wireguard`, both hops are WireGuard. Not for `warp tun`.
* `warp proxy --l4` (`CFRS_WARP_L4`): each TCP client is one HTTP/3
  `CONNECT` stream to the L4 door of WARP (UDP 443, TLS name of `--l4-sni`,
  `consumer-masque-proxy.cloudflareclient.com`), with no IP stack in
  between. UDP (SOCKS5 UDP ASSOCIATE) is not served, and the rules do not
  apply.
* `--transport wireguard` (a flag of `cfrs warp`, before or after the subcommand; `CFRS_WARP_TRANSPORT`): the tunnel on
  WireGuard (UDP, port 2408 of the record, or `--wireguard-endpoint`) in
  place of MASQUE. The device is the one of `cfrs warp export`
  (`warp-wg.json` in the state directory); cfrs registers it when the file
  has none. The stack, the proxy and the commands are the same. There is no
  relay and no proxy: WireGuard is UDP.
* `--masque-transport h3` (a flag of `cfrs warp`, before or after the subcommand; `CFRS_WARP_MASQUE_TRANSPORT`): the MASQUE
  session over HTTP/3 on UDP 443 in place of HTTP/2 on TCP 443. Each IP
  packet is an HTTP datagram (RFC 9297), so a lost packet does not stop the
  other flows. A packet larger than a datagram goes as a capsule on the
  request stream. There is no relay and no proxy: they carry TCP only.
* `--cc none|reno|cubic` (a flag of `cfrs warp`, before or after the subcommand; `CFRS_WARP_CC`): the congestion
  controller of the TCP connections of the userspace stack, for the data
  that it sends (an upload). The default is `none`: only the window of the
  peer limits it.
* `--listen-identity LISTEN=PATH` (repeatable): the clients of LISTEN use
  the WARP device of the identity file PATH (cfrs makes it when it does not
  exist), with a session of its own and its own address. The `--listen`
  listeners use `--identity`. One file is for one listener only. The ready
  document lists the listeners and their devices in `identities`.
* Rules of `warp proxy` (`-r KIND:VALUE=ACTION`, repeatable): KIND is
  `domain` (`NAME`, or `.NAME` for the name and the names under it) or
  `cidr` (`ADDR/PREFIX`, IPv4 or IPv6, or `@FILE` with one prefix on each
  line, for example the prefixes of a country). ACTION is `tunnel`,
  `direct` (from the host, with the resolver of the host and no proxy) or
  `reject` (SOCKS5 reply 0x02, HTTP 403). The first rule that matches wins.
  A name that no domain rule matches is resolved through the tunnel when a
  cidr rule exists. Then a loopback, a link-local or an unspecified address
  and `localhost` are refused, then `--rule-default` (`tunnel`) applies.
  `--rules-file FILE` adds the rules of FILE (one on each line, `#` starts a
  comment); cfrs reads it again when it changes and keeps the rules before
  when it has an error. `--check` prints the rules and exits. The rules
  apply to TCP; UDP goes through the tunnel. The health line counts the
  decisions.

  ```sh
  cfrs warp proxy -r domain:.corp.example=direct -r cidr:10.0.0.0/8=direct \
      -r domain:.ads.example=reject --rules-file ~/.config/cfrs/rules
  ```
* `cfrs warp run --backend netns-raw` runs the program in a user and network
  namespace whose TUN goes to WARP as raw IP packets: TCP, UDP, ICMP and
  IPv6, with the kernel stack of the namespace and no root. The TUN has the
  WARP addresses and the default routes, and the program gets a
  `resolv.conf` with 1.1.1.1. `--backend auto` takes it when this host can
  make the namespace (and no `-r` rule is given), else the pod below.
* `cfrs warp run` starts the proxy on a unix socket and runs the program with
  `cfrs pod` (`auto` takes the `seccomp` backend first, for UDP). It passes
  `-r` (for example `-r cidr:10.0.0.0/8=direct`), `--keep-proxy-env` and
  `--inbound-dir` to the pod. A connect to 127.0.0.1 goes to the host, not
  to WARP. The TCP connections and the DNS queries of the program go
  through WARP, also for static binaries. With the `seccomp` backend, other
  UDP datagrams also go through WARP (SOCKS5 UDP ASSOCIATE). ICMP (`ping`)
  goes through WARP only with `--backend netns-raw`; the pod does not carry
  it.
* `cfrs warp up [--port 40000] [--persist]` starts `warp proxy` in the
  background (instance `warp`, see "Run in the background") on
  `127.0.0.1:PORT` and on a unix socket, and writes an env file with the
  proxy variables. When the host refuses the TCP listener, `warp up` starts
  with the socket only: the env file has no proxy variables, `warp env` says
  so and exits 69 with no output, and `warp exec` and `warp shell` work. Later shells join it:
  * `eval "$(cfrs warp env)"`: `ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY`,
    `NO_PROXY` (and the lower-case forms), `CARGO_HTTP_PROXY` and the npm
    variables. The proxy also forwards `http://` URLs (for apt).
  * `cfrs warp exec -- CMD` and `cfrs warp shell`: the command runs under
    the pod of the socket: TCP, DNS and UDP go through WARP, also for static
    binaries, with no proxy variable.
  * `--persist`: a marked block in `~/.bashrc` and `~/.profile` loads the env
    file in each new shell, and an interactive shell runs under the pod.
  * `--env-d`: `$XDG_CONFIG_HOME/environment.d/90-cfrs-warp.conf`
    (`~/.config/environment.d/...` when the variable is not set) has the proxy
    variables. The systemd user manager gives them to the programs of the
    next login (a desktop, a browser, a user unit). A file of that name that
    cfrs did not write stays, and `warp up --env-d` stops with an error.
  * `cfrs warp down` stops the instance and removes the env file and the
    blocks (and the environment.d file of cfrs); the rest of each file
    stays.
  * The CA bundle: when `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
    `CURL_CA_BUNDLE` or `GIT_SSL_CAINFO` names a bundle of fewer than 10
    certificates (the roots of a proxy that terminates TLS), the tools that
    use it fail through WARP, which shows the real chains. `warp up` then
    writes `warp-ca.pem` (that bundle and the system bundle) and the env
    file, `warp exec` and `warp shell` name it, so that the proxy and WARP
    both work. With no system bundle, a warning says to unset the variable.
* `cfrs warp nc HOST PORT`: a byte pipe from stdin and stdout to HOST:PORT
  through the running `cfrs warp up` (else a WARP session of its own), for
  `ssh -o ProxyCommand='cfrs warp nc %h %p'` and git over SSH where port 22
  is closed. `--via-relay` goes through the WebSocket relay to HOST:PORT
  with no WARP. `cfrs warp ssh-config [--host PATTERN]` prints the SSH
  config block and a `GIT_SSH_COMMAND`. SSH checks the host key as on a
  direct connection. At the end of stdin, cfrs sends no FIN: the pipe ends
  when the far end closes, or `--idle` seconds (default 5) after the last
  data. `-N` sends the FIN at the end of stdin, for a server that waits for
  it. An error of the far end exits 69.
* `cfrs warp ssh-config --write --host github.com` puts the block in
  `~/.ssh/config` (or `--config FILE`), between two marker lines, before
  the first `Host` or `Match` line. A second `--write` replaces it (for
  example after cfrs moved). `--check` exits 1 when the block is missing or
  stale; `--remove [--host PATTERN]` removes it. No other line of the file
  changes. A `Host` line of the file with the same pattern is an error, and
  the files of `Include` are not read. `cfrs warp down` keeps the block.
  `--host` is one pattern of 1 to 255 characters from `A-Z a-z 0-9 . _ -
  * ? ! : @ % , [ ]`; a space, a newline or another control character
  exits 64, and nothing is printed or written.
* `cfrs warp tun --default-route` (CAP_NET_ADMIN) sends the whole host
  through WARP: a host route keeps each address of the MASQUE connection
  (the proxy, the front door, the relay) outside the TUN when the TUN
  would capture it. An address on loopback or on a connected subnet needs
  none, so a host with no default route works when its proxy is there; an
  address with no route at all is refused with its name. `0.0.0.0/1`,
  `128.0.0.0/1`, `::/1` and `8000::/1` go to the TUN; DNS goes to 1.1.1.1
  (`resolvectl` on the TUN, else `/etc/resolv.conf` with a copy kept). The
  default routes go away while the session is down, so traffic fails fast.
  The end (Ctrl-C, SIGTERM, `cfrs stop`) puts back each route and the
  resolver. The changes are ioctls; no script runs as root.
  `cfrs warp up --tun` starts it detached (instance `warp-tun`), and
  `cfrs warp down` stops it.
* `cfrs warp tun` makes a TUN interface with the tunnel address and moves its
  packets through WARP. It does not change the routes: add routes for the
  destinations to send through WARP, and keep a route for the MASQUE endpoint
  outside the interface. The command prints examples.
* `cfrs warp proxy`, `cfrs warp run` and `cfrs warp tun` open a new MASQUE
  session when the session ends (a network change, the front door, the
  limit of a relay): at once, then with a backoff of 1 s doubled to 30 s.
  A new client takes the new session; a client that comes while the
  session is down waits for it (20 s at most). `warp tun` keeps its
  interface. The log has `a new WARP session is open` for each.
* When the direct MASQUE path fails (a proxy that refuses CONNECT to an
  IP address, or that answers and carries nothing), cfrs opens the same
  MASQUE TLS through the WebSocket relay of `--relay` (default
  `https://tcp.ssh.relay.ajam.dev`, see "Edge protocol and transport"). The
  client certificate and the pinned key stay end to end. The path that
  worked goes first at the next session. `--no-relay` turns this off.
  `--masque-endpoint IP:PORT` and `--masque-sni NAME` replace the front
  door and its TLS name.
* The registration API calls and the MASQUE connection use the proxy (see
  "Proxies and DNS"). A proxy that terminates TLS cannot carry the MASQUE
  connection, because the connection uses a client certificate.

## Run any program through a proxy: `cfrs pod`

`cfrs pod` (the same as the `pod-netns` binary) runs a program with all its
network traffic sent through a SOCKS5, HTTP or tailnet upstream. It does not
use `LD_PRELOAD`, so static binaries and Go binaries are also covered.

```sh
cfrs pod -x socks5://127.0.0.1:1080 -- curl https://example.com
cfrs pod -x http://proxy:3128 -- git clone https://example.com/repo
cfrs pod -x socks5://unix:/run/proxy.sock -- ./static-binary
cfrs pod -- curl https://example.com        # upstream from $ALL_PROXY or $HTTPS_PROXY
cfrs pod doctor                             # which backend can run here
```

Two backends are available. `--backend auto` (the default) selects one.

| Backend | Needs | Mechanism |
| --- | --- | --- |
| `netns` | unprivileged user namespaces and `/dev/net/tun` | The program gets a network namespace. A TUN device is its only interface. A userspace TCP/IP stack sends each flow to the upstream. |
| `seccomp` | seccomp with `SECCOMP_RET_USER_NOTIF` | A seccomp filter stops the socket system calls. The supervisor answers them and gives the program connected descriptors. |

Both backends answer DNS from a fake-IP pool (`198.18.0.0/15`; the
`seccomp` backend answers AAAA from `fd63:6672:7300::/96` too) and send the
name to the upstream. Thus no DNS query leaves the host. See
[`crates/pod-netns/README.md`](https://github.com/Azathothas/cfrs/blob/main/crates/pod-netns/README.md) for all options.

## Virtual network: `cfrs net`

`cfrs net` gives programs IP addresses on a host that refuses `AF_INET` binds.
It needs no namespace, no TUN device and no capability.

```sh
cfrs net doctor                         # what this host permits
cfrs net shim --out /tmp/cfrsnet        # build the LD_PRELOAD shim
LD_PRELOAD=/tmp/cfrsnet/libcfrsnet.so ./server      # bind 10.66.0.2:8080 works
cfrs net proxy --forward 10.66.0.2:8080=unix:/run/app.sock
cfrs net switch --listen unix:/tmp/cfrsnet.switch   # connect stacks
cfrs net proxy --switch unix:/tmp/cfrsnet.switch --address 10.66.0.3
```

`cfrs net doctor` calls `bind` and then `listen` for each stream socket
(a policy can allow one and refuse the other; `SO_ACCEPTCONN` confirms the
listen), and sends one QUIC packet to the edge on UDP 7844: answered, refused
or `?` (no answer in 3 s). It prints the commands that need each listener.
`CFRS_UDP=off` makes a tunnel use no QUIC on UDP 7844; `CFRS_UDP=on` skips
the probe at start.

See [`docs/virtual-network.md`](https://github.com/Azathothas/cfrs/blob/main/docs/virtual-network.md).

## Tailscale on a sealed host

```sh
cfrs net tailscale --socket /run/tailscale/tailscaled.sock   # SOCKS5 front door to the tailnet
eval "$(cfrs net socksify --socket /tmp/cfrssocks.sock)"     # shim for tailnet connects
cfrs net ts-shims --out /run/cfrs-ts-shims                   # user tables for Tailscale SSH
cfrs pod -x tailscale:/run/tailscale/tailscaled.sock -- ssh host
```

`tailscaled` must run with `--tun=userspace-networking`.

## Proxies and DNS

Each connection of cfrs (the quick-tunnel API, DNS over HTTPS, the HTTP/2
edge leg, the WARP API, MASQUE, the fetch of the public URL) takes the same
proxy:

```sh
cfrs --proxy socks5h://127.0.0.1:1080 tunnel --url http://127.0.0.1:8080
HTTPS_PROXY=http://user:password@proxy:3128 cfrs demo --exit-on-verify
NO_PROXY=127.0.0.1,.internal cfrs warp register
cfrs --no-proxy tunnel --url http://127.0.0.1:8080
```

* The order: `--proxy` (or `CFRS_PROXY`), then `HTTPS_PROXY`,
  `https_proxy`, `ALL_PROXY`, `all_proxy`. A variable that is empty or does
  not parse is skipped. `--no-proxy` uses none.
* Percent-encode `/ ? # @ :` in the user and the password of a proxy URL
  (for example `%2F` for `/`).
* `http://` uses `CONNECT`. `socks5://` resolves the name on this host;
  `socks5h://` gives the name to the proxy. cfrs refuses `socks4://` and
  `https://`.
* A proxy on a unix socket: `socks5h+unix:/PATH` (also
  `socks5h://unix:/PATH`), or `http+unix:/PATH`.
* A proxy at the stdin and the stdout of a command, when the only way out
  is a byte channel (issue 129): `--proxy 'http+exec:ssh gw nc 127.0.0.1
  3128'`. Each connection starts the command once, with `sh -c`, as the
  `ProxyCommand` of SSH; its stderr is the stderr of cfrs. Only `--proxy`
  and `CFRS_PROXY` take `+exec:`: a variable of another tool does not start
  a program. QUIC legs need UDP and do not use it.
* Without `--proxy` and `--no-proxy`, cfrs reads `HTTPS_PROXY`,
  `https_proxy`, `ALL_PROXY` and `all_proxy`. `NO_PROXY` names the targets
  that do not use the proxy.
* When no proxy variable is set, cfrs takes the proxy of the first tool
  config that names one: `~/.gitconfig` and `~/.config/git/config`
  (`http.proxy`), `~/.npmrc` (`https-proxy`, else `proxy`),
  `~/.config/pip/pip.conf` and `~/.pip/pip.conf` (`proxy`),
  `/etc/gitconfig`, `/etc/pip.conf`, and `/etc/environment`. The log names
  the file. `--no-proxy` turns it off.
* With a proxy, `--protocol auto` does not try QUIC on UDP 7844 (no proxy
  carries UDP), and cfrs prints one line that says so. `--protocol quic`
  keeps QUIC, with a warning.
* With a user and a password, cfrs sends Basic. A proxy that answers 407
  with a Digest challenge (RFC 7616: MD5, MD5-sess, SHA-256,
  SHA-256-sess, `qop=auth`) gets the Digest answer on a new connection.
  Another 407 gets a message with the schemes that the proxy asks for. No
  NTLM.

A direct connection resolves the name with this chain: a pin of
`--resolve HOST=IP` or `CFRS_RESOLVE`, the system resolver, then DNS over
HTTPS by IP address at Cloudflare (1.1.1.1, 1.0.0.1) and Google (8.8.8.8,
8.8.4.4). It tries each address of the name, and starts the next attempt
250 ms after the one before.

## TLS roots

cfrs checks the certificate of each TLS server that it connects to. Behind a
proxy that inspects TLS, give the root of the proxy:

```sh
SSL_CERT_FILE=/etc/corp-root.pem cfrs tunnel --url http://127.0.0.1:8080
cfrs --ca-file /etc/corp-root.pem warp register
```

`--ca-file` and `SSL_CERT_FILE` replace the other roots. Without them, cfrs
trusts `cfrs-ca.pem` beside the binary, the first system bundle that it can
read (for example `/etc/ssl/certs/ca-certificates.crt`), and the Mozilla
roots compiled into cfrs. `cfrs status` shows the roots in `tls_roots`. See
`SECURITY.md`.

## One command for an agent sandbox: `cfrs agent up`

```sh
cfrs agent up --expose 3000      # test, start WARP if needed, expose port 3000
cfrs agent status
cfrs agent down                  # stop each part, put back each change
```

`cfrs agent up` runs the checks of `cfrs doctor --agent`. When direct
networking does not do each task (git over HTTPS and SSH, the registries,
UDP DNS), it starts `cfrs warp up` (`--persist` adds the shell block;
`--warp` starts it also when direct networking works). For each
`--expose PORT`, it starts a detached quick tunnel (instance
`expose-PORT`), and tries `--transport relay` when the first try fails.
It then runs the checks again and prints one JSON document: `mode`
(`warp` or `direct`), the paths that work for each task, the URLs, and
the commands to use (`eval "$(cfrs warp env)"`, `cfrs warp exec -- CMD`,
`cfrs warp ssh-config`).
When WARP was needed and `cfrs warp up` failed, the document has
`warp_error`, and the exit code is 69. When an expose failed (its `state`
in `exposed` is not `ready`), the exit code is 69 too.

## Inbound access through the relay: `cfrs relay`

A host with outbound HTTPS only cannot take inbound connections (SSH, a
debugger, a database client). A quick tunnel carries HTTP and WebSocket
only. The reverse mode of the WebSocket relay (`--relay`, default
`https://tcp.ssh.relay.ajam.dev`) carries raw TCP bytes to a local service.

```sh
# On the host:
cfrs relay pair                                   # name, connect token; the node token stays in a 0600 file
cfrs relay node --to 127.0.0.1:22 --detach        # hold the node socket; one local connection for each session

# On the computer of the operator:
export CFRS_RELAY_CONNECT_TOKEN=<connect token>
ssh -o ProxyCommand='cfrs relay connect NAME' USER@NAME
cfrs relay connect NAME --listen tcp://127.0.0.1:2222   # or a local port for each client

# On the host, at the end:
cfrs relay stop NAME
```

* `cfrs relay pair` asks the relay for a pair (`POST /v1/pair`). A pair lasts
  at most 72 h. The file is `relay/NAME.json` in the state directory, with
  mode 0600. `--json` prints the name, the connect token and the end time.
* `cfrs relay node [NAME] --to TARGET` takes the pair with the most time left
  when no name is given. `TARGET` is `host:port` or `unix:/path`. The node
  answers each `open` with `ready` after its local connection is ready, or
  with `reject` and the cause. A lost node socket is opened again after 1 s
  to 30 s, with jitter. The node warns 24 h, 6 h and 1 h before the pair
  expires. A node with no pair name takes the next stored pair at the
  expiry (a pair that `cfrs relay pair` made since), with no new start. Its
  operators need the name and the connect token of the next pair. When the
  relay ends the pair (it expired with no next pair, or `cfrs relay stop`
  ran), the node exits 78 and is not started again.
* `cfrs relay connect NAME` waits for `ready`, then copies stdin and stdout.
  A refused session exits 69 with the cause from the node. A refused token
  exits 78. After the end of stdin, the session ends when the node closes,
  or 15 s (the idle time of the relay) after the last data. A close of the
  relay other than 1000 (for example 1009 at its byte limit) or a lost link
  exits 69, also after the end of stdin: the output can be cut.
* The relay authenticates tokens, not persons. Give the connect token only
  over a channel that you trust. Check the host key of SSH as usual.
* The relay sets its own limits; cfrs does not enforce them. Measured on
  `tcp.ssh.relay.ajam.dev`: 64 MiB and 12 h for each session, and it can end
  a session after 180 s with no payload. Open a new session after a limit.

## Run in the background: `--detach`

```sh
cfrs tunnel --port 3000 --detach --name web   # prints one JSON line, exits 0
cfrs warp proxy --listen unix:/tmp/warp.sock --detach
cfrs ps                                        # name, state, pid, URL or listen address
cfrs logs web -f
cfrs wait web                                  # the ready document again (exit 124 at --timeout)
cfrs stop web                                  # or: cfrs stop --all
```

`--detach` works with `tunnel`, `serve`, `share`, `demo`, `connect`,
`warp proxy`, `warp forward`, `warp tun`, `relay node`, `net proxy` and
`net switch`. The command runs in the foreground until it
is ready: until the public URL answers, or until the listener is bound.
Then it leaves the terminal (`setsid`, SIGHUP ignored, stdin to
`/dev/null`, stdout and stderr to its log), and the start prints one JSON
document on stdout: `name`, `pid`, `log`, and `url` or `listen`. The lines
of the instance before the ready go to stderr.
The instance keeps running when the shell or the terminal closes. A sandbox
or a container that kills each process of its run also ends it.

* A second start with the same name and the same arguments prints the same
  document and starts nothing. Other arguments exit 69; `--replace` stops
  the instance and starts the new one.
* Without `--name`, the name is the command and a hash of its arguments.
* `--ready-timeout SECS` (default 60): after it, the start stops the
  instance and exits 124 (as `timeout`). An instance that ends before it is ready gives its
  own exit code.
* A token or a proxy password on the command line goes to the environment
  of the instance, not to its arguments or its record. The record of a
  foreground `--name` (no `--detach`) has no secret either.
* The files are in `$XDG_RUNTIME_DIR/cfrs/run/` (else `run` in the state
  directory, or `CFRS_RUN_DIR`), mode 0700: `NAME.json` (0600), `NAME.lock`
  (held while the instance runs), `NAME.secrets` (0600, only when the
  instance has a token or a proxy password: the variables that hold them)
  and `NAME.log` (0600, cut at 1 MiB; the
  part before goes to `NAME.log.1`). Each start writes a line
  `cfrs: ---- start TIME pid PID name NAME ----`, then its log lines from
  the start (also the lines before the ready, which the start shows too).
  The log has no colour codes.
* A supervisor starts the instance again when it ends, with a backoff of
  1 s doubled to 30 s, but not after exit 64 or 78, and not before the first
  ready. A planned end is not restarted: `--stop-after`, `--idle-secs` and
  `--run-for` end the instance for good (a crash or a kill still restarts
  it). When the quick-tunnel service refused a provision with a
  `Retry-After` (HTTP 429), the next start waits that long (at most 1 h),
  and the run is not a quick failure. After 5 quick failures in sequence it
  runs `cfrs.prev` (the binary before the last `cfrs update`). A quick
  tunnel gets a new URL at a restart: `cfrs ps` shows it, and the log has a
  line for it.
  `--no-restart` turns the supervisor off. `cfrs stop` stops the supervisor
  and its instance.
* cfrs never removes a lock file that a live process holds. When the
  record of a live instance cannot be read, `cfrs ps` shows the instance
  with the state `unknown`, and `cfrs stop` exits 69 and removes nothing.
  `cfrs stop --all` goes on to the next instance after a failure.
* `cfrs autostart add NAME --from INSTANCE` makes a detached instance start
  at boot too. It copies the arguments of the record and the secrets of
  `INSTANCE.secrets`.
* `cfrs status` lists the instances.
* `--name NAME` with no `--detach` registers the process in the foreground
  (for a program that runs cfrs as its child): it is not forked and not
  restarted, its stdout and stderr stay, and its log lines go to `NAME.log`
  too. `cfrs ps`, `logs`, `wait` and `stop` see it. A second process with
  the name fails ("runs already"). `--replace` needs `--detach`.

## Autostart

`cfrs autostart` starts a cfrs command at boot and after a logout, with no
root. It uses a systemd user unit when `systemctl --user` answers, else an
`@reboot` line in the crontab. With neither, it prints the line to run at
login and exits 69.

```sh
TUNNEL_TOKEN=... cfrs autostart add web -- tunnel --url http://127.0.0.1:8080
cfrs autostart list
cfrs autostart remove web
```

* The arguments and the variables (`TUNNEL_TOKEN`, the proxy variables,
  `SSL_CERT_FILE`, `CFRS_*`) go to private files (mode 0600) in
  `<state>/autostart/`. `--token` and a `--proxy` with a password move to
  `TUNNEL_TOKEN` and `CFRS_PROXY`. The unit, the crontab line and the
  command line of the process hold no secret.
* The unit and the line run this binary by its absolute path. A binary in
  a temporary directory is refused. The unit quotes for systemd (`%` and
  `$` are escaped), the crontab line for `sh`.
* An entry runs in the foreground under its service manager: `add`
  removes `--detach`, `--name`, `--ready-timeout` and `--no-restart`, and
  says so.
* A systemd user manager stops at logout unless linger is on:
  `loginctl enable-linger`.
* `remove` deletes only what `add` wrote (a marker line in the unit, a
  marker comment on the crontab line).
* Each program that `add` or `remove` runs has a limit of 10 s.
* With no systemd user manager and no cron, `add` exits 69. Its error text
  gives a `nohup` line: put it in a login script (for example
  `~/.profile`).

## Doctor

`cfrs doctor` tests the path from this host to the edge, and gives `ok`,
`fail` or `unknown` for each hop (the words of `cfrs net doctor` and
`cfrs doctor --agent` too). In `--json`, the key is `status`; the old key
`verdict` has the same value for one release:

* the proxy of each target (the password is never printed), and the
  targets that `NO_PROXY` sends direct;
* TCP to `api.trycloudflare.com:443`, `api.cloudflareclient.com:443`, the
  edge on 7844 by name and by address, the MASQUE front door
  (`162.159.198.2:443`) and the WebSocket relay (`CFRS_RELAY`). A name is
  resolved first, with the chain of cfrs: the addresses and the time, or
  the error. Each path gets up to 9 samples, 125 ms apart, in
  at most 10 s: best, median, p95, jitter and loss. A refusal (a proxy 403,
  a TCP reset) is an answer, not a loss;
* TLS on each open path: the issuer, and if the chain ends at the roots that
  cfrs expects. A proxy that answers 200 and then sends no byte, and a proxy
  that terminates TLS, are named;
* names and addresses: if the proxy allows one and refuses the other;
* UDP 7844: one QUIC packet (answered, refused or unknown);
* the clock: this host against the `Date` of the first API that answers
  TLS. More than 300 s off is `fail` (certificates and tokens fail).

Then a table of the legs `quic`, `http2`, `quic+warp` and `http2+relay`
(TCP and TLS to the relay; the relay protocol is not tried), with the
reason for each leg that cannot work, and the roads: `direct` (quic or
http2), `warp` (quic+warp) and `relay` (http2+relay). The last line,
`next:`, gives the step to take: the `cfrs tunnel` command for the legs
that work, the clock to set, or the report for an issue (`next` in
`--json`). Exit 0: at least one leg can work. Exit 1: none can. `--json` gives one document; `--samples` and `--timeout`
make it shorter.

```sh
cfrs doctor
cfrs doctor --json | jq '.legs'
```

### What dev work can do: `cfrs doctor --agent`

```sh
cfrs doctor --agent           # a table and the commands to run
cfrs doctor --agent --json
```

For each task (git over HTTPS and over SSH, pip, npm, cargo, go modules,
docker pull), the doctor tries three paths: `direct`, the proxy of the
environment, and a running `cfrs warp up`. A TLS check is a handshake
with the public roots: `tls-intercepted` means that the chain is not
public but the CA bundle of this host (`SSL_CERT_FILE`) trusts it, so a
proxy or a gateway terminates TLS. It also tests UDP DNS to 1.1.1.1,
IPv6 and TCP on 127.0.0.1, and prints the commands: for example
`cfrs warp up`, `cfrs warp ssh-config`, or "nothing to do".

## Manual, status and exit codes

`cfrs man` shows the manual. It is generated from the command tree of the
binary, so it always agrees with `--help`. It needs no man(1), no groff and no
network.

```sh
cfrs man                      # the whole manual, in a pager on a terminal
cfrs man warp run             # one command
cfrs man exit-status          # one topic: environment, files, exit-status, examples, pod
cfrs man --roff > cfrs.1      # a man(7) page (also a release asset)
cfrs man --json               # the tables, for a program
cfrs status                   # one JSON line about this host; no network
cfrs ports --json             # the listening TCP ports, as one JSON object
cfrs completions bash > ~/.local/share/bash-completion/completions/cfrs
cfrs -q tunnel ...            # warnings and errors only; -v debug, -vv trace
cfrs --log-format json ...    # the log as one JSON object for each line
cfrs --color never ...        # colours: auto (a terminal, no NO_COLOR), always, never
```

cfrs raises the soft limit of open files (`ulimit -n`) to the hard limit at
start, at most 1048576. `cfrs status` shows it in `nofile`. `warp exec`,
`warp shell`, `warp run` and `autostart run` keep the limit of the shell for
the program.

With `--json`, `cfrs tunnel`, `serve`, `share` and `demo` write JSON lines on
stdout in place of the text lines. A line with `"event": "ready"` gives
`url`, `tunnel_id`, `locations` and `leg` (and `pin` for `share`). `leg` is
the edge leg that carries the tunnel: `quic`, `http2`, `quic+warp` or
`http2+relay`. The text `edge` line names it too. A line with
`"event": "verified"` comes after the fetch of the public URL. Its `dns`
field names the resolver step that resolves the public name at that time:
`system`, `doh` (public DNS resolves it, the system resolver of this host
not yet: a visitor whose resolver cached NXDOMAIN gets an error for some
seconds more), `pin` (`--resolve`) or `none`. While the fetch fails, cfrs
logs the first try and each fifth try at INFO, and each try after the tenth
at WARN.

Stop signals: from the ready line (or the `ready` event) of a server
command on, SIGINT (Ctrl-C), SIGTERM and SIGHUP each start the clean
shutdown, also during the verify of the public URL and with `--run-for`.
A stop before the `verified` event gives no `verified` event. The exit
code is 0. A second signal during the shutdown stops cfrs at once. Before
the ready, each signal has its default action. A detached instance ignores
SIGHUP. When the parent ignores SIGHUP (`nohup`), cfrs ignores it too.

`--check` on `tunnel`, `serve`, `share` and `demo` checks the plan and stops.
It tests the flags and the config file, each origin (a connection, and the
TLS handshake for `https`; no request is sent), the files and the
directories (`--dir`, `--spa` and its `index.html`, `--file`, the upload
directory, `--warp-identity`, `--credentials-file`), `CFRS_EDGE` and the edge
legs (the `legs` row is the plan: `cfrs doctor` tests the reach of each
leg). It makes no Cloudflare API call and no edge connection, opens no
listening socket and writes no file. It prints no token and no PIN. Exit 0:
each check passed. Exit 1: a check of an origin failed. Exit 78: each
failed check is a check of the configuration (`CFRS_EDGE`, the credentials
file, the roots). A bad command line (64) or a bad config file (78) stops
before the check. With `--json`, the output is one
document: `{"ok", "plan", "checks": [{"name", "status", "detail"}]}`.

```sh
cfrs serve --check --dir ./site --spa
cfrs tunnel --check --json --config config.yml | jq -e .ok
```

The exit codes follow sysexits.h: 64 for a bad command line, 69 when a
service or a network path is not available (no edge leg worked), 78 for a
bad configuration (for example `CFRS_EDGE`). `cfrs man exit-status` gives all
of them.

`CFRS_ERROR_PROGRAM=/path/to/program` gives a JSON report of each failure
(version, system, command, exit code, the last 64 log lines) to that program
on its stdin. Credentials are masked. The program does not get
`TUNNEL_TOKEN`, the relay tokens, or a proxy variable with a user and a
password in its environment. Use it to collect failures in tests.

## Library

```rust
use cfrs::{Service, Tunnel};

# async fn run() -> anyhow::Result<()> {
let handle = Tunnel::quick()
    .service(Service::parse("http://127.0.0.1:8080")?)
    .ha_connections(2)
    .build()?
    .start()
    .await?;
println!("{:?}", handle.url());
handle.verify(None).await?;
handle.shutdown().await;
# Ok(())
# }
```

* `cfrs::Ingress` holds ordered rules for a tunnel with more than one service.
* `cfrs::warp::WarpClient` registers a device and opens a `WarpStack`, which
  has `tcp_connect` and `udp_bind` through the tunnel.
* `cfrs::vnet::NetStack` is the userspace IP stack.
* `pod_netns::main_with_args` runs the `pod-netns` command line. The modules
  `pod_netns::upstream`, `socks`, `dns` and `tailscale` are also public.

## Build

```sh
cargo build --release
```

The binaries are `target/release/cfrs` and `target/release/pod-netns`. Rust
1.89 or newer is necessary.

A static binary has no run-time dependency on the C library of the host:

```sh
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=clang cargo build --release --target x86_64-unknown-linux-musl
```

The `LD_PRELOAD` shims need a C compiler at run time (`cc`, `gcc` or
`clang`). The other commands do not.

### Fuzz

`fuzz/` has a libFuzzer target for each parser of bytes from the network
(Cap'n Proto, the RPC of the edge, capsules, proxy URLs and answers, SRV
and DoH, ACL rules, ingress rules, YAML, HTTP/2 headers, vnet frames, the
request head to the origin). It
needs a nightly toolchain and glibc. `.github/workflows/fuzz.yml` runs each
target each week. A crash input becomes a unit test before the fix.

```sh
cargo +stable install cargo-fuzz --locked --version 0.13.1
cd fuzz
cargo +nightly-2026-10-15 run --bin seed -- corpus
cargo +nightly-2026-10-15 fuzz run capnp_message corpus/capnp_message -- -max_total_time=60 -malloc_limit_mb=64
```

`cargo test` runs each target on its seeds and on 2000 fixed mutations
(`fuzzing::tests::each_target_survives_mutations`).

### Rebuild a release

`scripts/rebuild.sh TAG [TARGET]` rebuilds `cfrs` and `pod-netns` of a
release from its tag, at another path, in the pinned image of
`images/build/Dockerfile` of the tag, with the command of `release.yml`.
The two binaries must have the SHA-256 of `SHA256SUMS`. TARGET is
`x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl` (the default is
the one of the machine). It needs git, curl and docker
(`CONTAINER=podman` for podman). `release-proofs.yml` runs it for both
targets after each release.

```sh
sh scripts/rebuild.sh <TAG>
```

## Documents

* [`docs/protocol.md`](https://github.com/Azathothas/cfrs/blob/main/docs/protocol.md): the edge protocol and the WARP protocol.
* [`docs/virtual-network.md`](https://github.com/Azathothas/cfrs/blob/main/docs/virtual-network.md): the shim, the stack and switch mode.
* [`crates/pod-netns/README.md`](https://github.com/Azathothas/cfrs/blob/main/crates/pod-netns/README.md): pod-netns.
* [`docs/target-environment.md`](https://github.com/Azathothas/cfrs/blob/main/docs/target-environment.md): the measured
  hosts, the other host conditions, and the rules of cfrs for them.
* [`SECURITY.md`](https://github.com/Azathothas/cfrs/blob/main/SECURITY.md): how to report a vulnerability, what
  Cloudflare can see, what listens, where secrets are kept.

## License

0BSD. See [`LICENSE`](https://github.com/Azathothas/cfrs/blob/main/LICENSE). See
[`THIRD_PARTY_NOTICES.md`](https://github.com/Azathothas/cfrs/blob/main/THIRD_PARTY_NOTICES.md) for the licenses of the
included third-party files.
