//! The arguments of `podnet warp`: the global options and the subcommands.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::cli::opts::DetachArgs;

/// A license key of the command line: one character or more (issue 178:
/// an empty key went to the API).
pub(crate) fn non_empty_key(value: &str) -> std::result::Result<String, String> {
    let key = value.trim();
    if key.is_empty() {
        return Err("give a license key".into());
    }
    Ok(key.to_string())
}

#[derive(Args, Debug)]
#[command(subcommand_required = true, arg_required_else_help = false)]
pub(crate) struct WarpArgs {
    /// The file that keeps the device and its MASQUE key, so that each run
    /// uses the same device. Default: warp.json in the state directory
    /// (see PODNET_STATE_DIR in podnet man environment).
    #[arg(long, value_name = "PATH", global = true)]
    pub(crate) identity: Option<PathBuf>,
    /// Register a new device for this run only, and do not save it.
    #[arg(long, global = true, conflicts_with = "identity")]
    pub(crate) ephemeral: bool,
    /// A resolver of the DNS inside the tunnel, in place of 1.1.1.1:53:
    /// IP[:PORT] (UDP), or tls://IP[:PORT][#NAME] (DNS over TLS, port 853;
    /// the certificate must have NAME, or the IP address). Repeatable; the
    /// first that answers wins.
    #[arg(
        long,
        value_name = "SPEC",
        global = true,
        env = "PODNET_WARP_RESOLVERS",
        hide_env_values = true,
        value_delimiter = ','
    )]
    pub(crate) resolver: Vec<String>,
    /// The name of a new device in the dashboard (1 to 64 characters).
    #[arg(
        long,
        value_name = "NAME",
        global = true,
        env = "PODNET_WARP_DEVICE_NAME",
        hide_env_values = true
    )]
    pub(crate) device_name: Option<String>,
    /// The model that a new device declares (default PC).
    #[arg(
        long,
        value_name = "MODEL",
        global = true,
        env = "PODNET_WARP_DEVICE_MODEL",
        hide_env_values = true
    )]
    pub(crate) device_model: Option<String>,
    /// The locale that a new device declares, as en_US (default en_US).
    #[arg(
        long,
        value_name = "LOCALE",
        global = true,
        env = "PODNET_WARP_DEVICE_LOCALE",
        hide_env_values = true
    )]
    pub(crate) device_locale: Option<String>,
    /// Split the TLS ClientHello of the MASQUE connection into records:
    /// record (records of --fragment-size bytes) or sni (the first record
    /// ends in the server name). off: one record (the default).
    #[arg(
        long,
        value_name = "MODE",
        global = true,
        env = "PODNET_WARP_FRAGMENT", hide_env_values = true,
        num_args = 0..=1,
        default_missing_value = "record"
    )]
    pub(crate) fragment_client_hello: Option<String>,
    /// The bytes of handshake data in each record of
    /// --fragment-client-hello: N or MIN-MAX, 16 to 4096 (default 64-160).
    #[arg(
        long,
        value_name = "MIN[-MAX]",
        global = true,
        env = "PODNET_WARP_FRAGMENT_SIZE",
        hide_env_values = true
    )]
    pub(crate) fragment_size: Option<String>,
    /// The congestion controller of the TCP connections of the userspace
    /// stack (what the stack sends): none (the default), reno or cubic.
    #[arg(
        long,
        value_name = "NAME",
        global = true,
        env = "PODNET_WARP_CC",
        hide_env_values = true
    )]
    pub(crate) cc: Option<String>,
    /// Close each MASQUE session on purpose at this age, and open a new one
    /// (a new egress address). The TCP flows of the old session end.
    /// Default: off.
    #[arg(
        long,
        value_name = "SECS",
        global = true,
        env = "PODNET_WARP_SESSION_MAX_AGE", hide_env_values = true,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub(crate) session_max_age: Option<u64>,
    /// The TCP probe of the data path: IP:PORT or off (default 1.1.1.1:443). After 3
    /// failed connects (one each 30 s), a new session takes the new flows (warp tun: a SYN).
    #[arg(long, value_name = "IP:PORT|off", global = true, value_parser = podnet::warp::live::parse_probe)]
    pub(crate) probe: Option<Option<podnet::warp::live::Probe>>,
    /// Do not try the WebSocket relay (--relay, PODNET_RELAY) when the direct
    /// MASQUE path fails. Without it, podnet tries the relay: the TLS to the
    /// front door stays end to end in the WebSocket.
    #[arg(long, global = true)]
    pub(crate) no_relay: bool,
    /// The MASQUE front door (IP:PORT) in place of the one of the device.
    #[arg(long, value_name = "IP:PORT", global = true)]
    pub(crate) masque_endpoint: Option<std::net::SocketAddr>,
    /// The TLS name of the MASQUE front door in place of
    /// consumer-masque.cloudflareclient.com.
    #[arg(long, value_name = "NAME", global = true)]
    pub(crate) masque_sni: Option<String>,
    /// The transport of the MASQUE session: h2 (HTTP/2 on TCP 443, the
    /// default) or h3 (HTTP/3 on UDP 443: each packet is a QUIC datagram;
    /// no proxy and no relay).
    #[arg(
        long,
        value_name = "PROTOCOL",
        global = true,
        env = "PODNET_WARP_MASQUE_TRANSPORT", hide_env_values = true,
        value_parser = ["h2", "h3"]
    )]
    pub(crate) masque_transport: Option<String>,
    /// The leg of the tunnel: masque (the default) or wireguard (UDP to the
    /// WireGuard front door, with the device of `podnet warp export`, which
    /// podnet registers when the file has none).
    #[arg(
        long,
        value_name = "TRANSPORT",
        global = true,
        env = "PODNET_WARP_TRANSPORT", hide_env_values = true,
        value_parser = ["masque", "wireguard"]
    )]
    pub(crate) transport: Option<String>,
    /// The WireGuard front door (IP:PORT) in place of the one of the
    /// device record (port 2408).
    #[arg(
        long,
        value_name = "IP:PORT",
        global = true,
        env = "PODNET_WARP_WG_ENDPOINT",
        hide_env_values = true
    )]
    pub(crate) wireguard_endpoint: Option<std::net::SocketAddr>,
    /// wg: a second WireGuard device inside the tunnel (its own device in
    /// warp-carry.json of the state directory); the tools use its stack.
    /// With --transport wireguard, both hops are WireGuard.
    #[arg(
        long,
        value_name = "CARRY",
        global = true,
        env = "PODNET_WARP_CARRY", hide_env_values = true,
        value_parser = ["none", "wg"]
    )]
    pub(crate) carry: Option<String>,
    /// The front door (IP:PORT) of the carried device in place of the one
    /// of its record.
    #[arg(
        long,
        value_name = "IP:PORT",
        global = true,
        env = "PODNET_WARP_CARRY_ENDPOINT",
        hide_env_values = true
    )]
    pub(crate) carry_endpoint: Option<std::net::SocketAddr>,

    #[command(subcommand)]
    pub(crate) command: WarpCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum WarpCommand {
    /// Register a device (or load the saved one) and print it.
    Register,
    /// Print the device and the account (type, WARP+ state, quota).
    Status {
        /// Print the account record as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Attach a WARP+ license key to the device.
    License {
        /// The license key, or - to read it from stdin (it is then not on
        /// the command line).
        #[arg(value_parser = non_empty_key)]
        key: String,
    },
    /// Make a new MASQUE key and enrol it. The old key stops working.
    Rotate,
    /// Remove the device from the WARP service and delete the saved file.
    Delete,
    /// Open the tunnel and test TCP connects through it. Exit 69 when a
    /// target fails.
    Probe {
        /// A TCP destination to reach through the tunnel, host:port.
        #[arg(long, value_delimiter = ',')]
        target: Vec<String>,
    },
    /// Open the tunnel and print its exit: the data center (colo), the
    /// country and the address that a destination sees (from
    /// http://1.1.1.1/cdn-cgi/trace), and the IPv6 egress address (the
    /// trace at 2606:4700:4700::1111, else the TXT of whoami.cloudflare).
    /// Exit 69 when there is no answer.
    Exit {
        /// Print one JSON object.
        #[arg(long)]
        json: bool,
        /// Do not ask for the IPv6 egress address.
        #[arg(long)]
        no_ipv6: bool,
    },
    /// Print a WireGuard config of a new WARP device (wg-quick or JSON),
    /// for other clients. The device and its private key are in
    /// warp-wg.json of the state directory, not in warp.json. Its data
    /// path is WireGuard on UDP (port 2408), not MASQUE on TCP 443. The
    /// output holds the private key: a terminal is refused with no --out
    /// (--out - prints it), and a redirected file becomes mode 0600. WARP
    /// reads 3 reserved bytes in each message; kernel WireGuard and
    /// wg-quick send zeros. --check tells if the device needs the bytes.
    Export(podnet::warp::export::command::Args),
    /// Measure front doors of WARP: the TCP connect and the TLS handshake
    /// with the pinned key, for each --candidate and the front doors of the
    /// device record. The fastest goes first. Exit 69 when none answers.
    Scan {
        /// A front door to measure: IP or IP:PORT (port 443); an IPv6
        /// address with a port is in brackets. Repeatable.
        #[arg(long, value_name = "IP[:PORT]", value_delimiter = ',')]
        candidate: Vec<String>,
        /// The time limit of each front door, in milliseconds (100 to
        /// 60000).
        #[arg(long, value_name = "MS", default_value_t = 3000,
              value_parser = clap::value_parser!(u64).range(100..=60_000))]
        timeout_ms: u64,
        /// Print one JSON document.
        #[arg(long)]
        json: bool,
    },
    /// Forward local listeners through WARP (as ssh -L): each connection to
    /// LISTEN goes through the tunnel to HOST:PORT.
    Forward {
        /// LISTEN=HOST:PORT. LISTEN is PORT (on 127.0.0.1), ADDR:PORT,
        /// tcp://ADDR:PORT or unix:/PATH. HOST is resolved inside the
        /// tunnel; a tunnel: prefix is accepted. Repeatable.
        #[arg(
            short = 'L',
            long = "local",
            value_name = "LISTEN=HOST:PORT",
            required_unless_present = "list",
            env = "PODNET_WARP_FORWARD",
            hide_env_values = true,
            value_delimiter = ','
        )]
        local: Vec<String>,
        /// Print the forwards of the detached instances (podnet ps) and exit.
        #[arg(long)]
        list: bool,
        /// Exit 69 when any listener does not start.
        #[arg(long)]
        strict: bool,
        /// The most connections of each listener at the same time. 0: no
        /// limit.
        #[arg(long, value_name = "N", default_value_t = 32)]
        max_connections: usize,
        /// Stay up for this many seconds instead of until Ctrl-C.
        #[arg(long)]
        run_for: Option<u64>,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Run a local SOCKS5 and HTTP CONNECT proxy whose traffic goes through
    /// WARP (the proxy mode of the WARP client).
    Proxy {
        /// Where to accept clients: tcp://host:port or unix:/path.
        /// Repeatable: each listener serves the same WARP session.
        /// A listener that the host refuses is reported, and the proxy
        /// starts with the others; with none, the exit code is 69.
        #[arg(long, default_value = "tcp://127.0.0.1:40000")]
        listen: Vec<String>,
        /// Exit 69 when any listener does not start.
        #[arg(long)]
        strict: bool,
        /// The most clients at the same time; a client over it is closed
        /// at once, with a warning in the log. 0: no limit.
        #[arg(long, value_name = "N", default_value_t = 0)]
        max_connections: u64,
        /// Also answer DNS on this UDP address (for example
        /// 127.0.0.1:5353): each query goes through WARP to 1.1.1.1.
        #[arg(long, value_name = "ADDR")]
        dns: Option<std::net::SocketAddr>,
        /// Clients must give this user (SOCKS5 user and password, or HTTP
        /// Basic), with the password of --proxy-password-file.
        #[arg(
            long,
            value_name = "USER",
            env = "PODNET_PROXY_USER",
            hide_env_values = true,
            requires = "proxy_password_file"
        )]
        proxy_user: Option<String>,
        /// The file with the password of --proxy-user on its first line
        /// (mode 0600).
        #[arg(
            long,
            value_name = "FILE",
            env = "PODNET_PROXY_PASSWORD_FILE",
            hide_env_values = true,
            requires = "proxy_user"
        )]
        proxy_password_file: Option<PathBuf>,
        /// A rule for the destinations: KIND:VALUE=ACTION. KIND is domain
        /// (NAME, or .NAME for the name and the names under it) or cidr
        /// (ADDR/PREFIX, IPv4 or IPv6, or @FILE with one prefix on each
        /// line). ACTION is tunnel, direct (from the host, with no proxy)
        /// or reject. The first rule that matches wins. Repeatable.
        #[arg(
            short = 'r',
            long = "rule",
            value_name = "KIND:VALUE=ACTION",
            env = "PODNET_WARP_RULES",
            hide_env_values = true,
            value_delimiter = ','
        )]
        rules: Vec<String>,
        /// Serve each TCP client on its own HTTP/3 CONNECT stream to the L4
        /// door of WARP (UDP 443), with no IP stack. UDP is not served. The
        /// rules (-r, --rules-file, --rule-default) apply; an address rule
        /// (cidr:) decides an address, not a name, as no name is resolved.
        #[arg(long, env = "PODNET_WARP_L4", hide_env_values = true, conflicts_with_all = ["dns", "listen_identity"])]
        l4: bool,
        /// The TLS name of the L4 door.
        #[arg(long, value_name = "NAME", default_value = podnet::warp::l4::l4_sni(), requires = "l4")]
        l4_sni: String,
        /// LISTEN=PATH: a listener whose clients use the WARP device of the
        /// identity file PATH (made when it does not exist: that registers
        /// a new device), with a session of its own. The --listen listeners
        /// use --identity. Repeatable; each PATH once.
        #[arg(long, value_name = "LISTEN=PATH")]
        listen_identity: Vec<String>,
        /// A file with one rule on each line (# starts a comment), after
        /// the --rule rules. podnet reads it again when it changes.
        #[arg(
            long,
            value_name = "FILE",
            env = "PODNET_WARP_RULES_FILE",
            hide_env_values = true
        )]
        rules_file: Option<PathBuf>,
        /// The action when no rule matches.
        #[arg(long, value_name = "ACTION", default_value = "tunnel")]
        rule_default: String,
        /// Check the rules, print them, and exit (0, or 64 for a bad rule).
        #[arg(long)]
        check: bool,
        /// Stay up for this many seconds instead of until Ctrl-C.
        #[arg(long)]
        run_for: Option<u64>,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Start WARP for this sandbox, in the background: a
    /// detached warp proxy on 127.0.0.1:PORT and on a unix socket, and an
    /// env file with the proxy variables. Later shells join it with
    /// `eval "$(podnet warp env)"`, `podnet warp exec -- CMD`, `podnet warp
    /// shell`, or --persist.
    Up {
        /// The TCP port of the proxy on 127.0.0.1.
        #[arg(long, default_value_t = 40000)]
        port: u16,
        /// Add a marked block to ~/.bashrc and ~/.profile: each new shell
        /// loads the env file, and an interactive shell runs under the pod
        /// (static binaries and UDP go through WARP too). podnet warp down
        /// removes it.
        #[arg(long)]
        persist: bool,
        /// Also write the proxy variables to
        /// $XDG_CONFIG_HOME/environment.d/90-podnet-warp.conf (else
        /// ~/.config/environment.d/90-podnet-warp.conf): the systemd user
        /// manager gives them to the programs of the next login (a
        /// desktop, a user unit). podnet warp down removes the file. A file
        /// of that name that podnet did not write is not changed.
        #[arg(long)]
        env_d: bool,
        /// Seconds to wait for WARP to be ready.
        #[arg(long, default_value_t = 90)]
        ready_timeout: u64,
        /// With CAP_NET_ADMIN: send the whole host through WARP with warp
        /// tun --default-route (instance warp-tun), in place of the proxy.
        #[arg(long, conflicts_with = "persist")]
        tun: bool,
        /// Stop a running warp up with other arguments (another --port),
        /// and start this one.
        #[arg(long)]
        replace: bool,
        /// Also answer DNS on this UDP address (for example
        /// 127.0.0.1:5353): each query goes through WARP to 1.1.1.1.
        #[arg(long, value_name = "ADDR")]
        dns: Option<std::net::SocketAddr>,
        /// Clients must give this user (SOCKS5 user and password, or HTTP
        /// Basic), with the password of --proxy-password-file.
        #[arg(
            long,
            value_name = "USER",
            env = "PODNET_PROXY_USER",
            hide_env_values = true,
            requires = "proxy_password_file"
        )]
        proxy_user: Option<String>,
        /// The file with the password of --proxy-user on its first line
        /// (mode 0600).
        #[arg(
            long,
            value_name = "FILE",
            env = "PODNET_PROXY_PASSWORD_FILE",
            hide_env_values = true,
            requires = "proxy_user"
        )]
        proxy_password_file: Option<PathBuf>,
    },
    /// Stop what podnet warp up started, and remove its env file and its
    /// block in ~/.bashrc and ~/.profile.
    Down,
    /// Print the proxy variables of the running podnet warp up, for
    /// `eval "$(podnet warp env)"`. Exit 69 with no output when warp up has no
    /// TCP listener (no proxy variables).
    Env,
    /// Run a program under the pod of the running podnet warp up: TCP, DNS
    /// and UDP go through WARP, also for static binaries.
    Exec {
        /// A podnet-netns rule, repeatable (see podnet pod --help).
        #[arg(short = 'r', long = "rule", value_name = "SPEC")]
        rules: Vec<String>,
        #[command(flatten)]
        at: podnet::warp::pod::PodOptions,
        /// The program and its arguments.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        program: Vec<String>,
    },
    /// Run $SHELL under the pod of the running podnet warp up. When it does
    /// not run, the shell starts as it is (with the proxy variables when
    /// the env file is there).
    Shell(podnet::warp::pod::PodOptions),
    /// A byte pipe from stdin and stdout to HOST:PORT through WARP, for
    /// `ssh -o ProxyCommand='podnet warp nc %h %p'` and git over SSH.
    /// It uses the running podnet warp up, else a WARP session of its
    /// own.
    Nc {
        host: String,
        port: u16,
        #[command(flatten)]
        at: podnet::warp::find::At,
        /// Go through the WebSocket relay (--relay) to HOST:PORT, with no
        /// WARP (TCP, IPv4).
        #[arg(long, conflicts_with = "udp")]
        via_relay: bool,
        /// UDP: each read of stdin is one datagram to HOST:PORT; each
        /// datagram that comes back goes to stdout.
        #[arg(short = 'u', long)]
        udp: bool,
        /// After the end of stdin, end when no data came for this many
        /// seconds (default 3 with -u, else 5). TCP: podnet then sends the FIN.
        #[arg(long, value_name = "SECS")]
        idle: Option<u64>,
        /// TCP: send the FIN at the end of stdin, then wait for the far end
        /// to close (as nc -N). Without it, podnet sends no FIN until the end:
        /// some servers drop a half-closed connection before they answer.
        #[arg(short = 'N', long, conflicts_with = "udp")]
        shutdown: bool,
    },
    /// Print an SSH config block and GIT_SSH_COMMAND that use podnet warp nc.
    /// With --write, --remove or --check: own the block in the SSH config
    /// file, between two marker lines.
    SshConfig {
        /// The Host pattern of the block (default * for the printed block;
        /// --write and --check need one).
        #[arg(long)]
        host: Option<String>,
        /// Add the block for --host to the SSH config file, or replace it.
        /// The block goes before the first Host or Match line. A Host line
        /// of the file that names the same pattern is an error (exit 1).
        #[arg(long, conflicts_with_all = ["remove", "check"])]
        write: bool,
        /// Remove the block for --host (with no --host: each block of podnet).
        #[arg(long, conflicts_with = "check")]
        remove: bool,
        /// Exit 1 when the block for --host is missing or names another
        /// binary. Writes nothing.
        #[arg(long)]
        check: bool,
        /// The SSH config file.
        #[arg(long, value_name = "FILE", default_value = "~/.ssh/config")]
        config: String,
    },
    /// Make a TUN interface whose packets go through WARP. Needs
    /// CAP_NET_ADMIN and /dev/net/tun. Routes are not changed.
    Tun {
        /// The interface name.
        #[arg(long, default_value = "podnet0")]
        interface: String,
        /// Send the whole host through WARP: host routes keep the
        /// MASQUE connection outside, default routes go to the TUN (IPv4 and
        /// IPv6), DNS goes to 1.1.1.1. The default routes go away while the
        /// session is down; each change is put back at the end.
        #[arg(long)]
        default_route: bool,
        /// Keep the rp_filter of the interface. Without it, podnet writes 0.
        #[arg(long)]
        keep_rp_filter: bool,
        #[command(flatten)]
        detach: DetachArgs,
    },
    /// Run a program with all its traffic sent through WARP. No root and no
    /// TUN device are necessary (podnet-netns).
    Run {
        /// The backend: auto, netns-raw, netns or seccomp. netns-raw moves the
        /// raw packets of a namespace through WARP (TCP, UDP, ICMP, IPv6; no
        /// root). auto takes netns-raw when it works, else seccomp, so that
        /// UDP goes through WARP too.
        #[arg(long, default_value = "auto")]
        backend: String,
        /// A podnet-netns rule, repeatable: domain:NAME=PROXY,
        /// domain:.SUFFIX=PROXY, cidr:NET/LEN=PROXY; PROXY may be direct.
        #[arg(short = 'r', long = "rule", value_name = "SPEC")]
        rules: Vec<String>,
        /// The program keeps the proxy variables of this shell.
        #[arg(long)]
        keep_proxy_env: bool,
        /// Where a port that the program listens on is a unix socket
        /// (seccomp backend). The directory must be of this user and not
        /// writable by the group or others [default:
        /// $XDG_RUNTIME_DIR/podnet-netns-inbound, else
        /// $TMPDIR/podnet-netns-inbound-UID].
        #[arg(long, value_name = "DIR")]
        inbound_dir: Option<PathBuf>,
        /// The program and its arguments.
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        program: Vec<String>,
    },
}
