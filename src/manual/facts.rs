//! The tables of the manual that the command tree does not hold: the
//! variables of the environment, the files, and the examples. The tests check
//! the variables against the source code, and `main` checks each example
//! with the parser of the binary.

use serde::Serialize;

/// One variable of the environment.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct EnvVar {
    /// The names: the first is the main name, the others are aliases.
    pub names: &'static [&'static str],
    /// The part of cfrs that reads it.
    pub used_by: &'static str,
    pub meaning: &'static str,
}

/// Each variable that cfrs, pod-netns or the shims read.
pub const ENVIRONMENT: &[EnvVar] = &[
    EnvVar {
        names: &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"],
        used_by: "tunnel, warp, edge discovery, pod",
        meaning: "The proxy for each connection of cfrs, when --proxy and --no-proxy are not given: http://, socks5:// (this host resolves the name) or socks5h:// (the proxy resolves it), [user:password@]host[:port]. The first variable that is set and can be parsed is used. With a proxy, --protocol auto does not try QUIC on UDP 7844. pod-netns uses the value as its default upstream.",
    },
    EnvVar {
        names: &["NO_PROXY", "no_proxy"],
        used_by: "all commands",
        meaning: "The targets that do not use the proxy, separated by commas: * (all), a name (it matches the names under it too), .name, an IP address, a network (10.0.0.0/8), each with an optional :port.",
    },
    EnvVar {
        names: &["CFRS_RESOLVE"],
        used_by: "all commands",
        meaning: "Addresses for names, in place of DNS: HOST=IP[,HOST=IP]. --resolve adds to it. Without a pin, cfrs asks the system resolver, then DNS over HTTPS at 1.1.1.1, 1.0.0.1, 8.8.8.8 and 8.8.4.4.",
    },
    EnvVar {
        names: &["HTTP_PROXY", "http_proxy"],
        used_by: "pod",
        meaning: "The default upstream of pod-netns when HTTPS_PROXY and ALL_PROXY are not set.",
    },
    EnvVar {
        names: &["TUNNEL_TOKEN"],
        used_by: "tunnel, serve, share, demo",
        meaning: "The named-tunnel token, in place of --token. Other users of the host can read a command line, but not the environment of a process of another user.",
    },
    EnvVar {
        names: &["SSL_CERT_FILE"],
        used_by: "all commands",
        meaning: "The only file of TLS roots (PEM), when --ca-file is not given. Without both, cfrs trusts cfrs-ca.pem beside the binary, the first system bundle that it can read, and the roots compiled into cfrs.",
    },
    EnvVar {
        names: &["CFRS_STATE_DIR"],
        used_by: "warp, tunnel --transport warp",
        meaning: "The state directory (the WARP identity). The value none keeps no file. Without it, cfrs takes the first directory that it can write of $XDG_STATE_HOME/cfrs, $HOME/.local/state/cfrs, $XDG_RUNTIME_DIR/cfrs and cfrs-<uid> in the temporary directory.",
    },
    EnvVar {
        names: &["XDG_STATE_HOME", "HOME", "XDG_RUNTIME_DIR", "TMPDIR"],
        used_by: "warp, net shim, net socksify, autostart",
        meaning: "The candidates of the state directory, and of the directory of a shim (a directory that is not noexec). cfrs reads the home from HOME only, not from the user database.",
    },
    EnvVar {
        names: &["XDG_CONFIG_HOME"],
        used_by: "autostart",
        meaning: "The base of the systemd user unit: $XDG_CONFIG_HOME/systemd/user/cfrs-NAME.service, else $HOME/.config/systemd/user.",
    },
    EnvVar {
        names: &["CFRS_LEG_FAILOVER"],
        used_by: "tunnel, serve, share, demo",
        meaning: "The value of --leg-failover when the flag is not given: staggered or serial.",
    },
    EnvVar {
        names: &["NO_COLOR"],
        used_by: "all commands",
        meaning: "When set, the log has no colours. The log has colours only when stderr is a terminal.",
    },
    EnvVar {
        names: &["CFRS_EDGE"],
        used_by: "tunnel, serve, share, demo, doctor, net doctor",
        meaning: "A comma-separated list of ip:port edge addresses. It replaces edge discovery. A value that cannot be parsed is a configuration error (exit 78).",
    },
    EnvVar {
        names: &["CFRS_PROXY"],
        used_by: "all commands",
        meaning: "The value of --proxy when the flag is not given: http://, socks5:// or socks5h://HOST:PORT, SCHEME+unix:/PATH, or SCHEME+exec:COMMAND (a proxy at the stdin and stdout of a command). It keeps a proxy password out of the command line; cfrs autostart puts it in the private env file of an entry. The env file of cfrs warp up with no TCP listener sets it to the unix socket.",
    },
    EnvVar {
        names: &["CFRS_WARP_SHELL"],
        used_by: "warp shell, the block of warp up --persist",
        meaning: "Set in a shell that cfrs warp shell started; the block of --persist then does not start it again.",
    },
    EnvVar {
        names: &["SHELL"],
        used_by: "warp shell",
        meaning: "The shell that cfrs warp shell runs (default /bin/sh).",
    },
    EnvVar {
        names: &["CFRS_RUN_DIR"],
        used_by: "--detach, ps, stop, logs, wait",
        meaning: "The directory of the detached instances (mode 0700): NAME.json, NAME.lock and NAME.log for each. Default: $XDG_RUNTIME_DIR/cfrs/run, else run in the state directory.",
    },
    EnvVar {
        names: &["CFRS_DETACH_NAME", "CFRS_DETACH_HASH", "CFRS_DETACH_COMMAND", "CFRS_DETACH_SUPERVISED"],
        used_by: "--detach",
        meaning: "cfrs sets them for the child of --detach: the name of the instance, the hash of its arguments, the command, and whether a supervisor runs it. Do not set them.",
    },
    EnvVar {
        names: &["CFRS_RELAY"],
        used_by: "tunnel, serve, share, demo, relay",
        meaning: "The value of --relay when the flag is not given: the WebSocket-to-TCP relay of --transport relay (https:// and a host). The default is https://tcp.ssh.relay.ajam.dev.",
    },
    EnvVar {
        names: &["CFRS_RELAY_TOKEN"],
        used_by: "tunnel, serve, share, demo",
        meaning: "A token for the relay of --transport relay. It goes only in the X-Relay-Token header. Without it, cfrs mints a token with POST /v1/mint on the relay.",
    },
    EnvVar {
        names: &["CFRS_RELAY_CONNECT_TOKEN"],
        used_by: "relay connect",
        meaning: "The connect token of a pair, for the operator side of the reverse relay. It goes only in the X-Relay-Token header. Without it, cfrs reads the local pair file.",
    },
    EnvVar {
        names: &["POD_NETNS_TEST_MEM"],
        used_by: "pod (tests only)",
        meaning: "A test hook of the seccomp backend: no-fd does not open the memory of the program for writing (process_vm_writev is used); none also does not use process_vm_writev (getsockname and getpeername fail with EOPNOTSUPP).",
    },
    EnvVar {
        names: &["CFRS_WARP_TCP_BURST"],
        used_by: "warp proxy, warp run, warp up, agent up",
        meaning: "The TCP window of the userspace stack of WARP, in segments of the MTU: a number from 1 to 430 (default 1), or none: for a measurement of throughput. Another value is a configuration error (exit 78).",
    },
    EnvVar {
        names: &["CFRS_WARP_MASQUE_TRANSPORT"],
        used_by: "warp (each command that opens a MASQUE session), warp up (its proxy)",
        meaning: "The value of --masque-transport: h2 (HTTP/2 on TCP 443, the default) or h3 (HTTP/3 on UDP 443; each IP packet is an HTTP datagram). h3 has no relay and no proxy.",
    },
    EnvVar {
        names: &["CFRS_WARP_TRANSPORT", "CFRS_WARP_WG_ENDPOINT"],
        used_by: "warp (each command that opens a session), warp up (its proxy)",
        meaning: "The value of --transport (masque, the default, or wireguard) and of --wireguard-endpoint (IP:PORT). wireguard carries the tunnel on UDP to the WireGuard front door (port 2408 of the record) with the device of warp export (warp-wg.json of the state directory), which cfrs registers when the file has none. It has no relay and no proxy.",
    },
    EnvVar {
        names: &["CFRS_WARP_L4"],
        used_by: "warp proxy",
        meaning: "Set to true: the value of --l4. Each TCP client of the proxy is one HTTP/3 CONNECT stream to the L4 door of WARP on UDP 443 (TLS name of --l4-sni), with no IP stack; UDP is not served.",
    },
    EnvVar {
        names: &["CFRS_WARP_CC"],
        used_by: "warp (each command with a userspace stack), warp up (its proxy), tunnel --transport warp",
        meaning: "The value of --cc: the congestion controller of the TCP connections of the userspace stack of WARP, for the data that the stack sends: none (the default; only the window of the peer limits it), reno (RFC 5681) or cubic (RFC 9438). Another value is a configuration error (exit 78).",
    },
    EnvVar {
        names: &["CFRS_WARP_NO_CHECK"],
        used_by: "warp proxy, warp run, warp up, warp probe, warp exit, warp nc, agent up",
        meaning: "Set and not empty: a new MASQUE session is used with no check of its data path. By default, one DNS query through the session must get an answer (5 s) before the session is up; else the session is closed and cfrs tries again. For a measurement.",
    },
    EnvVar {
        names: &["POD_NETNS_QUIET"],
        used_by: "pod, warp exec, warp shell, warp run",
        meaning: "Set and not empty: the pod prints no warnings (errors stay). cfrs -q sets it.",
    },
    EnvVar {
        names: &["CFRS_PROXY_USER", "CFRS_PROXY_PASSWORD_FILE"],
        used_by: "warp proxy, warp up",
        meaning: "The value of --proxy-user and --proxy-password-file: each client of the proxy must give this user and the password on the first line of the file (mode 0600), with SOCKS5 (RFC 1929) or HTTP Basic. A client with no or wrong credentials gets 0xff, 0x01 or 407.",
    },
    EnvVar {
        names: &["CFRS_WARP_DEVICE_NAME", "CFRS_WARP_DEVICE_MODEL", "CFRS_WARP_DEVICE_LOCALE"],
        used_by: "warp (each command that registers a device), tunnel --transport warp",
        meaning: "The value of --device-name, --device-model and --device-locale: what a new device declares at its registration (a name of 1 to 64 characters, a model of 1 to 32, a locale as en_US). With none, the request is as before (model PC, locale en_US, no name). A bad value is a usage error (exit 64). A saved device does not change.",
    },
    EnvVar {
        names: &["CFRS_WARP_FRAGMENT", "CFRS_WARP_FRAGMENT_SIZE"],
        used_by: "warp (each command that opens a MASQUE session), warp up (its proxy)",
        meaning: "The value of --fragment-client-hello (off, record or sni) and --fragment-size (N or MIN-MAX, 16 to 4096 bytes; default 64-160): the TLS ClientHello of the MASQUE connection goes in more than one record. sni ends the first record in the server name. A bad value is a configuration error (exit 78).",
    },
    EnvVar {
        names: &["CFRS_WARP_RULES", "CFRS_WARP_RULES_FILE"],
        used_by: "warp proxy, warp up (its proxy reads them)",
        meaning: "The value of -r/--rule (comma-separated KIND:VALUE=ACTION) and of --rules-file: the rules of the destinations of the proxy. KIND is domain or cidr (IPv4, IPv6, or @FILE of prefixes); ACTION is tunnel, direct or reject. The file is read again when it changes. A bad rule is a usage error (exit 64).",
    },
    EnvVar {
        names: &["CFRS_WARP_FORWARD"],
        used_by: "warp forward",
        meaning: "The value of -L/--local, comma-separated: LISTEN=HOST:PORT. Each connection to LISTEN (PORT on 127.0.0.1, ADDR:PORT, tcp://ADDR:PORT or unix:/PATH) goes through WARP to HOST:PORT; HOST is resolved inside the tunnel. A loopback target is a usage error (exit 64).",
    },
    EnvVar {
        names: &["CFRS_WARP_RESOLVERS"],
        used_by: "warp proxy, warp up, warp run, warp tun, warp probe, warp nc, tunnel --transport warp",
        meaning: "The value of --resolver: the DNS resolvers inside the tunnel, comma-separated, in place of 1.1.1.1:53. IP[:PORT] is DNS on UDP; tls://IP[:PORT][#NAME] is DNS over TLS (RFC 7858, port 853), with the certificate checked for NAME or the IP address. The first that answers wins. warp tun --default-route writes the UDP ones on port 53 to resolv.conf.",
    },
    EnvVar {
        names: &["CFRS_UDP"],
        used_by: "tunnel, serve, share, demo, doctor",
        meaning: "QUIC on UDP 7844: off (no QUIC on UDP 7844), on (no probe), or probe (the default). With probe and --protocol auto, cfrs sends one QUIC packet to the edge while it starts; when the send or the path refuses it, cfrs does not try QUIC on UDP 7844. No answer keeps the order of the legs. Another value is a configuration error (exit 78). cfrs doctor shows the quic leg refused with off; cfrs net doctor always sends its probe.",
    },
    EnvVar {
        names: &["CFRS_ERROR_PROGRAM"],
        used_by: "all commands",
        meaning: "A program that gets a JSON report on its stdin when cfrs fails (exit code not 0). It runs with no shell and no arguments, for at most 30 s. The report has the version, the system, the command, the exit code, the error (\"error\": the error and its causes, once) and the log lines before it (\"messages\": at most 64), with credentials masked. A usage error (exit 64) sends a report too.",
    },
    EnvVar {
        names: &["RUST_LOG"],
        used_by: "all commands",
        meaning: "The log filter, for example cfrs=debug. The default is cfrs=info.",
    },
    EnvVar {
        names: &["CFRS_DEBUG"],
        used_by: "serve (SSH relay)",
        meaning: "When set, log each visitor channel of the SSH relay transport.",
    },
    EnvVar {
        names: &["PAGER", "TERM", "LESS", "LINES"],
        used_by: "man",
        meaning: "The pager of cfrs man on a terminal: PAGER (empty or cat: no pager), else less when PATH has it and TERM is not dumb, else the built-in pager. When LESS is not set, less gets LESS=FRX. The built-in pager shows LINES lines (default: the terminal height).",
    },
    EnvVar {
        names: &["PATH"],
        used_by: "pod, man, net shim",
        meaning: "pod-netns finds the program to run in PATH. cfrs man finds less, and cfrs net shim finds the C compiler.",
    },
    EnvVar {
        names: &["CC"],
        used_by: "net shim, net socksify, net ts-shims",
        meaning: "The C compiler that builds the LD_PRELOAD shims. The default is cc, then gcc, then clang.",
    },
    EnvVar {
        names: &["USER"],
        used_by: "net ts-shims",
        meaning: "The default login name of the synthetic user.",
    },
    EnvVar {
        names: &["LD_PRELOAD"],
        used_by: "net shim, net socksify",
        meaning: "The printed environment adds the shim in front of the current value.",
    },
    EnvVar {
        names: &["CFRSNET_SHIM", "CFRSSOCKS_SHIM"],
        used_by: "net shim, net socksify",
        meaning: "The path of a shim that is already built. cfrs uses it instead of a build.",
    },
    EnvVar {
        names: &["CFRSNET_LOG", "CFRSNET_MAP_LOOPBACK", "CFRSNET_LOCAL_ADDR", "CFRSNET_PREFIX", "CFRSNET_HOSTS", "CFRSNET_CONTROL", "CFRSNET_MAX_FDS"],
        used_by: "libcfrsnet.so",
        meaning: "The shim of the virtual network: log each translation; map 127.0.0.1 to the local virtual address; the local virtual IPv4 address; the prefix of the abstract names; a name=address table; the abstract name of the control socket; the size of the descriptor table.",
    },
    EnvVar {
        names: &["CFRSSOCKS_PROXY", "CFRSSOCKS_LOG", "CFRSSOCKS_ALL", "CFRSSOCKS_MAX_FDS"],
        used_by: "libcfrssocks.so",
        meaning: "The tailnet shim: the unix socket of the SOCKS5 front door; log each redirect; redirect each connect, not only tailnet addresses; the size of the descriptor table.",
    },
    EnvVar {
        names: &["SANDHOME_PASSWD", "UNIXSOCKD_LOG"],
        used_by: "net ts-shims, unixsockd",
        meaning: "The passwd file that fakepwd.so reads; log each connection of unixsockd.",
    },
    EnvVar {
        names: &["CFRS_BUILD_COMMIT"],
        used_by: "the build",
        meaning: "Read when cfrs is compiled: the commit that --version prints.",
    },
];

/// One file or directory.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct FileEntry {
    pub path: &'static str,
    pub meaning: &'static str,
}

/// Each file that cfrs reads or writes.
pub const FILES: &[FileEntry] = &[
    FileEntry {
        path: "<state directory>/warp.json",
        meaning: "The WARP device, its token and its MASQUE key (mode 0600, directory mode 0700). The state directory is the first that cfrs can write of CFRS_STATE_DIR, $XDG_STATE_HOME/cfrs, $HOME/.local/state/cfrs, $XDG_RUNTIME_DIR/cfrs and cfrs-<uid> in the temporary directory; never the current directory. cfrs warp writes it; cfrs warp delete removes it. --identity names another file.",
    },
    FileEntry {
        path: "cfrs-ca.pem (beside the binary)",
        meaning: "Extra TLS roots (PEM), for example the root of a TLS-inspecting proxy. cfrs reads it when --ca-file and SSL_CERT_FILE are not set.",
    },
    FileEntry {
        path: "/etc/ssl/certs/ca-certificates.crt",
        meaning: "The first system bundle of TLS roots. cfrs also tries /etc/pki/tls/certs/ca-bundle.crt, /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem, /etc/ssl/ca-bundle.pem, /etc/ssl/cert.pem and /usr/local/share/certs/ca-root-nss.crt, and reads the first that it can.",
    },
    FileEntry {
        path: "config.yml (--config)",
        meaning: "A cloudflared configuration file: tunnel, credentials-file, ha-connections, protocol, ingress.",
    },
    FileEntry {
        path: "~/.cloudflared/<tunnel-id>.json (--credentials-file)",
        meaning: "The credentials of a named tunnel, as cloudflared writes them.",
    },
    FileEntry {
        path: "/tmp/cfrsnet.socks",
        meaning: "The default listen address of cfrs net proxy.",
    },
    FileEntry {
        path: "/tmp/cfrsnet.switch",
        meaning: "The default listen address of cfrs net switch.",
    },
    FileEntry {
        path: "/tmp/cfrssocks.sock",
        meaning: "The default listen address of cfrs net tailscale.",
    },
    FileEntry {
        path: "/tmp/cfrs-warp-<pid>.sock",
        meaning: "The proxy socket of cfrs warp run, for the life of the command.",
    },
    FileEntry {
        path: "/tmp/pod-netns-inbound/<port>.sock",
        meaning: "A port that a program under cfrs pod listens on (--inbound-dir).",
    },
    FileEntry {
        path: "$TMPDIR/cfrsnet, $TMPDIR/cfrssocks, $TMPDIR/cfrs-ts-shims",
        meaning: "The default build directories of the shims.",
    },
];

/// One example of the manual.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Example {
    pub command: &'static str,
    pub meaning: &'static str,
}

/// The examples. Each `cfrs` line is parsed by the parser of the binary in
/// the tests of `main.rs`.
pub const EXAMPLES: &[Example] = &[
    Example {
        command: "cfrs update --check",
        meaning: "Say whether a newer release exists. cfrs update installs it after it checks the cosign signature and the SHA-256.",
    },
    Example {
        command: "cfrs demo --exit-on-verify",
        meaning: "Make a quick tunnel to the built-in origin, and fetch its public URL.",
    },
    Example {
        command: "cfrs tunnel --url http://127.0.0.1:8080",
        meaning: "A quick tunnel to a local HTTP server.",
    },
    Example {
        command: "cfrs tunnel --unix /run/app.sock",
        meaning: "A quick tunnel to an HTTP server on a unix socket.",
    },
    Example {
        command: "cfrs tunnel --protocol http2 --url http://127.0.0.1:8080",
        meaning: "Use the HTTP/2 edge leg on TCP 7844 (no UDP).",
    },
    Example {
        command: "cfrs tunnel --transport warp --hello-world",
        meaning: "Reach the edge through WARP on TCP 443 only.",
    },
    Example {
        command: "cfrs tunnel --token TOKEN --url http://127.0.0.1:8080",
        meaning: "A named tunnel.",
    },
    Example {
        command: "cfrs tunnel --config config.yml",
        meaning: "Ingress rules from a cloudflared configuration file.",
    },
    Example {
        command: "cfrs tunnel --forward unix:/run/app.sock",
        meaning: "Carry a raw stream through the quick tunnel.",
    },
    Example {
        command: "cfrs connect wss://NAME.trycloudflare.com/__cfrs/ws -L tcp://127.0.0.1:8080",
        meaning: "The client side of --forward.",
    },
    Example {
        command: "cfrs serve --dir ./public",
        meaning: "Serve a directory.",
    },
    Example {
        command: "cfrs share --mode upload --password",
        meaning: "Receive files, with a PIN.",
    },
    Example {
        command: "cfrs warp status",
        meaning: "The WARP device and account.",
    },
    Example {
        command: "cfrs warp proxy --listen tcp://127.0.0.1:40000",
        meaning: "A SOCKS5 and HTTP CONNECT proxy through WARP.",
    },
    Example {
        command: "cfrs warp run -- curl https://www.cloudflare.com/cdn-cgi/trace",
        meaning: "Run a program with its traffic through WARP.",
    },
    Example {
        command: "cfrs pod -x socks5://127.0.0.1:1080 -- curl https://example.com",
        meaning: "Run a program with all its traffic through a proxy.",
    },
    Example {
        command: "cfrs net proxy --forward 10.66.0.2:8080=unix:/run/app.sock",
        meaning: "A virtual address for a real service.",
    },
    Example {
        command: "cfrs status",
        meaning: "One JSON line about this host, for a program.",
    },
    Example {
        command: "cfrs man --roff",
        meaning: "This manual as a man(7) page.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The variable names in the source: env::var("X"), var_os("X"),
    /// getenv("X"), and the names of the proxy lists.
    fn names_in_source() -> BTreeSet<String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for dir in ["src", "crates/pod-netns/src", "shim"] {
            collect(&root.join(dir), &mut files);
        }
        files.push(root.join("build.rs"));
        // Cargo sets these for build.rs; they are not variables of cfrs.
        const CARGO_BUILD: &[&str] = &["TARGET"];
        let mut names = BTreeSet::new();
        for file in files {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            for marker in [
                "env::var(\"",
                "env::var_os(\"",
                "getenv(\"",
                "var(\"",
                "var_os(\"",
                "env = \"",
            ] {
                for (i, _) in text.match_indices(marker) {
                    let rest = &text[i + marker.len()..];
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_uppercase() || *c == '_' || c.is_ascii_digit())
                        .collect();
                    if name.len() > 1 && rest[name.len()..].starts_with('"') {
                        names.insert(name);
                    }
                }
            }
            // A constant that names a variable: `const X_VARIABLE: &str = "NAME";`.
            for line in text.lines() {
                let line = line.trim();
                if !line.starts_with("//") && line.contains("_VARIABLE: &str = \"") {
                    if let Some(name) = line.split('"').nth(1) {
                        names.insert(name.to_string());
                    }
                }
            }
            for list in [
                "\"HTTPS_PROXY\"",
                "\"ALL_PROXY\"",
                "\"HTTP_PROXY\"",
                "\"NO_PROXY\"",
            ] {
                if text.contains(list) {
                    names.insert(list.trim_matches('"').to_string());
                }
            }
        }
        for name in CARGO_BUILD {
            names.remove(*name);
        }
        names
    }

    fn collect(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs" || e == "c") {
                out.push(path);
            }
        }
    }

    fn documented() -> BTreeSet<String> {
        ENVIRONMENT
            .iter()
            .flat_map(|v| v.names.iter().map(|n| n.to_string()))
            .collect()
    }

    #[test]
    fn each_variable_in_the_source_is_in_the_manual() {
        let documented = documented();
        let missing: Vec<String> = names_in_source()
            .into_iter()
            .filter(|n| !documented.contains(n))
            .collect();
        assert!(
            missing.is_empty(),
            "variables read by the code but not in the manual: {missing:?}"
        );
    }

    #[test]
    fn each_variable_in_the_manual_is_read_by_the_source() {
        let found = names_in_source();
        // RUST_LOG is read by tracing-subscriber; lower-case aliases by name lists.
        let read_elsewhere = ["RUST_LOG"];
        let stale: Vec<String> = documented()
            .into_iter()
            .filter(|n| n.chars().all(|c| !c.is_ascii_lowercase()))
            .filter(|n| !found.contains(n) && !read_elsewhere.contains(&n.as_str()))
            .collect();
        assert!(
            stale.is_empty(),
            "variables in the manual that no code reads: {stale:?}"
        );
    }
}
