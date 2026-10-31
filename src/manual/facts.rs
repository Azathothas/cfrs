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
        meaning: "An HTTP proxy (http://[user:pass@]host:port) for the quick-tunnel service, DNS over HTTPS, the HTTP/2 edge leg, the WARP API and the MASQUE connection. The first variable that is set and can be parsed is used. pod-netns also accepts a socks5:// value as its default upstream.",
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
        names: &["CFRS_EDGE"],
        used_by: "tunnel",
        meaning: "A comma-separated list of ip:port edge addresses. It replaces edge discovery. A value that cannot be parsed is a configuration error (exit 78).",
    },
    EnvVar {
        names: &["CFRS_ERROR_PROGRAM"],
        used_by: "all commands",
        meaning: "A program that gets a JSON report on its stdin when cfrs fails (exit code not 0). It runs with no shell and no arguments, for at most 30 s. The report has the version, the system, the command, the exit code and the last 64 log lines, with credentials masked.",
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
        names: &["XDG_STATE_HOME", "HOME"],
        used_by: "warp",
        meaning: "The directory of the saved WARP identity: $XDG_STATE_HOME/cfrs/warp.json, else $HOME/.local/state/cfrs/warp.json, else ./cfrs-warp.json.",
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
        path: "$XDG_STATE_HOME/cfrs/warp.json",
        meaning: "The WARP device, its token and its MASQUE key (mode 0600). cfrs warp writes it; cfrs warp delete removes it. --identity names another file.",
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
            for list in ["\"HTTPS_PROXY\"", "\"ALL_PROXY\"", "\"HTTP_PROXY\""] {
                if text.contains(list) {
                    names.insert(list.trim_matches('"').to_string());
                }
            }
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
