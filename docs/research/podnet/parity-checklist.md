# Parity checklist: cfrs 0.3.0-beta.12 (3bed023) -> podnet

Tick each item when podnet has it with the same behaviour, or when a
ruling in `docs/decisions.md` records the change. Generated from
`cfrs man --json` of the binary of 3bed023 and from a scan of the
tests (`study/tools/gen_checklist.py`). Regenerate it on podnet and
diff the command tree: `podnet man --json | jq '.commands[].path'`.

Columns of the command sections:

* **always-on pins**: four unit tests of `src/main.rs` cover each command
  and each flag of the tree: `the_command_tree_is_valid` (clap debug
  assert), `each_help_screen_passes_the_lint`,
  `the_manual_names_each_command_and_flag`, `each_example_of_the_manual_parses`;
  and `tests/cli.rs::the_man_page_names_each_flag`. They pin that a flag
  exists and is documented, not what it does.
* **tests**: integration tests found by a scan of `tests/*.rs` (a test
  that runs the command). Library tests of the module are in section 11.
* **live**: steps of `.github/workflows/live.yml` (line of the step) and
  the scripts that the steps run.

## 1. Global options (each command)

- [ ] `--ca-file <PATH>`
- [ ] `--proxy <URL>` (env `CFRS_PROXY`)
- [ ] `--no-proxy`
- [ ] `--resolve <HOST=IP>`
- [ ] `-q, --quiet`
- [ ] `-v, --verbose`
- [ ] `--color <COLOR>` (default `auto`; values `auto`, `always`, `never`)
- [ ] `--log-format <LOG_FORMAT>` (default `text`; values `text`, `json`)

Pinned by: `tests/cli.rs` (`log_controls`, `log_format_json_gives_json_lines_only`,
`a_log_to_a_pipe_has_no_colours`, `bad_flag_values_are_usage_errors`,
`the_environment_is_checked_alike`, `status_names_the_kind_and_the_source_of_the_proxy`),
`tests/tls.rs` (`--ca-file`, `SSL_CERT_FILE`), `tests/egress.rs` (`--proxy`, `NO_PROXY`).

## 2. Behaviour of the entry point (`src/main.rs` `main()`)

- [ ] `cfrs pod ARGS` and `cfrs GLOBAL pod ARGS` hand the rest of argv to `pod_netns::main_with_args` before the runtime starts; a cfrs network option before `pod` is a usage error (64) (`tests/cli.rs::a_global_flag_before_pod_does_not_panic`, `main.rs::the_pod_keeps_its_double_dash`)
- [ ] `-q` sets `POD_NETNS_QUIET=1` for the pod
- [ ] cloudflared compatibility of `tunnel`: `tunnel run` = `tunnel`; `--no-autoupdate` dropped; `--loglevel debug|trace|warn|error|fatal|panic` -> `-v`/`-vv`/`-q` (`main.rs::cloudflared_arguments_work`)
- [ ] cloudflared flags with advice (usage hint, no flag): `--logfile`, `--log-directory`, `--pidfile`, `--metrics`, `--origincert`, `--autoupdate-freq`, `--grace-period`, `--edge-ip-version`, `--region`, `--retries`, `--tag`, `--post-quantum` (`CLOUDFLARED_FLAGS`)
- [ ] `--token-file PATH` / `TUNNEL_TOKEN_FILE` read into `TUNNEL_TOKEN` before the parse; for `relay connect` into `CFRS_RELAY_CONNECT_TOKEN`; `--token` with `--token-file` is an error; empty or >64 KiB file is an error (`tests/cli.rs::a_token_comes_from_a_file`)
- [ ] usage error: exit 64; with `--log-format json` the error is one JSON line; else clap text plus hints (port, URL, path, unknown word: `usage_hints`, `word_hint`) (`main.rs::a_word_that_is_no_command_gets_a_hint`, `an_unknown_command_names_the_version`, `a_bad_command_line_is_a_usage_error`)
- [ ] help exits 0; a missing subcommand (`cfrs net`) is 64
- [ ] the top help: groups `HELP_GROUPS` and the block `START_HERE`; each command in one group (`main.rs::each_command_is_in_one_help_group`)
- [ ] each command help ends with its examples from `manual::facts::EXAMPLES` (`main.rs::the_help_of_a_command_has_its_examples`)
- [ ] `rlimit::raise()` (soft limit of open files) for each command except `warp exec`, `warp shell`, `warp run`, `autostart run` (`tests/cli.rs::the_soft_limit_of_open_files_is_raised`)
- [ ] `--detach`: parent starts the supervisor and prints the ready document; `--detach-child` refused from a user; `--replace` needs `--detach` (except `connect`); `--name` without `--detach` registers the process; `--no-restart` needs `--detach` or `--name` (`tests/detach.rs`)
- [ ] `--ca-file` checked before any work: a bad file exits 78 for each command
- [ ] `network_options`: `--proxy`, `--no-proxy`, `--resolve`, `CFRS_RESOLVE` set once; a bad flag is 64, a bad variable keeps its class (78)
- [ ] SIGPIPE default action for `status`, `ports`, `qr`, `man`, `completions`, `doctor`, `net doctor`, `net addresses`, `net demo` (`tests/cli.rs::a_full_stdout_is_no_panic`)
- [ ] log level: `RUST_LOG` > `-v`/`-vv`/`-q`; a bad `RUST_LOG` gives a warning and the default level; colours only on a terminal, not with `NO_COLOR`, not in a detached child
- [ ] one info line for a server command in the foreground with no terminal (`tunnel`, `serve`, `share`, `connect`, `relay node`) unless `--detach`, `--run-for`, `--exit-on-verify` (`main.rs::a_foreground_server_with_no_terminal_gets_one_line`)
- [ ] signals: SIGINT, SIGTERM, SIGHUP start a clean stop; SIGHUP stays ignored when the parent ignored it (`tests/signals.rs`, `tests/cli.rs::sigterm_is_a_clean_stop`)
- [ ] a failure: one error line (text or JSON), `hop` line, exit code of `exit::code_of`, report to `CFRS_ERROR_PROGRAM`; a supervised child passes `retry_after_s` to the supervisor (`tests/cli.rs::the_failure_report_has_the_error_once`, `the_error_program_gets_no_secret`)
- [ ] `println!`/`eprintln!` drop a failed write (issue 74) in the binary and the library

## 3. Commands, subcommands and flags

### `cfrs tunnel`

- [ ] command exists: Expose a service (cloudflared-style)
  - [ ] `--detach`
  - [ ] `--name <NAME>`
  - [ ] `--ready-timeout <SECS>` (default `60`)
  - [ ] `--replace`
  - [ ] `--no-restart`
  - [ ] `--service-url <SERVICE_URL>` (default `https://api.trycloudflare.com`)
  - [ ] `--user-agent <USER_AGENT>`
  - [ ] `--ha-connections <HA_CONNECTIONS>`
  - [ ] `--protocol <PROTOCOL>` (values `auto`, `quic`, `http2`, `h2`)
  - [ ] `--transport <TRANSPORT>` (default `auto`; values `auto`, `direct`, `warp`, `relay`)
  - [ ] `--relay <URL>` (default `https://tcp.ssh.relay.ajam.dev`; env `CFRS_RELAY`)
  - [ ] `--warp-identity <PATH>`
  - [ ] `--leg-failover <LEG_FAILOVER>` (default `staggered`; env `CFRS_LEG_FAILOVER`; values `staggered`, `serial`)
  - [ ] `--no-verify`
  - [ ] `--qr`
  - [ ] `--json`
  - [ ] `--run-for <RUN_FOR>`
  - [ ] `--auth-user <USER>` (env `CFRS_AUTH_USER`)
  - [ ] `--auth-password-file <FILE>` (env `CFRS_AUTH_PASSWORD_FILE`)
  - [ ] `--check`
  - [ ] `--url <URL>`
  - [ ] `--unix <UNIX>`
  - [ ] `--port <PORT>`
  - [ ] `--tcp <TCP>`
  - [ ] `--forward <FORWARD>`
  - [ ] `--hello-world`
  - [ ] `--config <CONFIG>`
  - [ ] `--token <TOKEN>` (env `TUNNEL_TOKEN`)
  - [ ] `--token-file <PATH>` (env `TUNNEL_TOKEN_FILE`)
  - [ ] `--credentials-file <CREDENTIALS_FILE>`
  - [ ] `--no-tls-verify`
  - [ ] `--http-host-header <HTTP_HOST_HEADER>`
  - [ ] `--strip-accept-encoding`
- tests: `cli.rs::a_bad_configuration_exits_78`, `cli.rs::a_config_with_no_rule_fails_the_check`, `cli.rs::a_log_to_a_pipe_has_no_colours`, `cli.rs::a_missing_value_is_not_an_unknown_flag`, `cli.rs::a_token_comes_from_a_file`, `cli.rs::auth_user_flags`, `cli.rs::bad_credentials_exit_78`, `cli.rs::bad_flag_values_are_usage_errors`, `cli.rs::bad_input_gives_usage_errors_not_panics`, `cli.rs::check_mode`, `cli.rs::completion_scripts`, `cli.rs::error_messages_have_one_shape`, `cli.rs::exit_codes_of_flags_and_configuration`, `cli.rs::help_and_version_exit_0`, `cli.rs::log_controls`, `cli.rs::log_format_json_gives_json_lines_only`, `cli.rs::the_config_file_gives_the_protocol_and_the_connections`, `cli.rs::the_environment_is_checked_alike`, `cli.rs::the_error_program_gets_no_secret`, `cli.rs::the_failure_report_has_the_error_once`, `cli.rs::the_log_holds_no_secret`, `cli.rs::tunnel_tcp_takes_the_scheme_and_warns`, `detach.rs::no_ready_in_time_exits_75_and_leaves_no_record`, `docs.rs::the_readme_names_each_command_with_detach`, `egress.rs::a_407_names_the_schemes`, `egress.rs::a_proxy_refusal_names_the_hop_and_keeps_the_text`, `egress.rs::no_proxy_bypasses_the_proxy`, `egress.rs::socks5_carries_the_api_and_the_edge`, `egress.rs::socks5_resolves_the_target_with_the_pins`, `signals.rs::a_sigterm_to_pid_1_during_provisioning_stops_cfrs`; `src/main.rs`: `cloudflared_arguments_work`, `a_foreground_server_with_no_terminal_gets_one_line`, `a_sigterm_after_the_ready_line_stops_the_verify_cleanly`
- live: L113 SIGTERM; L132 --detach/ps/logs/stop; L152 --auth-user; L317 autostart unit; live-ws-url.sh; live-throughput.sh

### `cfrs serve`

- [ ] command exists: Serve a directory over a tunnel
  - [ ] `--detach`
  - [ ] `--name <NAME>`
  - [ ] `--ready-timeout <SECS>` (default `60`)
  - [ ] `--replace`
  - [ ] `--no-restart`
  - [ ] `--service-url <SERVICE_URL>` (default `https://api.trycloudflare.com`)
  - [ ] `--user-agent <USER_AGENT>`
  - [ ] `--ha-connections <HA_CONNECTIONS>`
  - [ ] `--protocol <PROTOCOL>` (values `auto`, `quic`, `http2`, `h2`)
  - [ ] `--transport <TRANSPORT>` (default `auto`; values `auto`, `direct`, `warp`, `relay`)
  - [ ] `--relay <URL>` (default `https://tcp.ssh.relay.ajam.dev`; env `CFRS_RELAY`)
  - [ ] `--warp-identity <PATH>`
  - [ ] `--leg-failover <LEG_FAILOVER>` (default `staggered`; env `CFRS_LEG_FAILOVER`; values `staggered`, `serial`)
  - [ ] `--no-verify`
  - [ ] `--qr`
  - [ ] `--json`
  - [ ] `--run-for <RUN_FOR>`
  - [ ] `--auth-user <USER>` (env `CFRS_AUTH_USER`)
  - [ ] `--auth-password-file <FILE>` (env `CFRS_AUTH_PASSWORD_FILE`)
  - [ ] `--check`
  - [ ] `--dir <DIR>` (required)
  - [ ] `--spa`
  - [ ] `--local <ADDR>`
  - [ ] `--token <TOKEN>` (env `TUNNEL_TOKEN`)
  - [ ] `--token-file <PATH>` (env `TUNNEL_TOKEN_FILE`)
- tests: `cli.rs::bad_credentials_exit_78`, `cli.rs::check_mode`, `cli.rs::error_messages_have_one_shape`, `cli.rs::serve_local_serves_files_on_a_unix_socket`, `cli.rs::serve_local_serves_files_on_tcp`
- live: -

### `cfrs share`

- [ ] command exists: Share files or a local port in a session with a PIN
  - [ ] `--detach`
  - [ ] `--name <NAME>`
  - [ ] `--ready-timeout <SECS>` (default `60`)
  - [ ] `--replace`
  - [ ] `--no-restart`
  - [ ] `--service-url <SERVICE_URL>` (default `https://api.trycloudflare.com`)
  - [ ] `--user-agent <USER_AGENT>`
  - [ ] `--ha-connections <HA_CONNECTIONS>`
  - [ ] `--protocol <PROTOCOL>` (values `auto`, `quic`, `http2`, `h2`)
  - [ ] `--transport <TRANSPORT>` (default `auto`; values `auto`, `direct`, `warp`, `relay`)
  - [ ] `--relay <URL>` (default `https://tcp.ssh.relay.ajam.dev`; env `CFRS_RELAY`)
  - [ ] `--warp-identity <PATH>`
  - [ ] `--leg-failover <LEG_FAILOVER>` (default `staggered`; env `CFRS_LEG_FAILOVER`; values `staggered`, `serial`)
  - [ ] `--no-verify`
  - [ ] `--qr`
  - [ ] `--json`
  - [ ] `--run-for <RUN_FOR>`
  - [ ] `--auth-user <USER>` (env `CFRS_AUTH_USER`)
  - [ ] `--auth-password-file <FILE>` (env `CFRS_AUTH_PASSWORD_FILE`)
  - [ ] `--check`
  - [ ] `--mode <MODE>` (values `upload`, `download`, `proxy`)
  - [ ] `--dir <DIR>`
  - [ ] `--file <FILE>`
  - [ ] `--port <PORT>`
  - [ ] `--unix <PATH>`
  - [ ] `--password`
  - [ ] `--stop-after`
  - [ ] `--idle-secs <IDLE_SECS>` (default `900`)
  - [ ] `--max-request <BYTES>` (default `100000000`)
  - [ ] `--token <TOKEN>` (env `TUNNEL_TOKEN`)
  - [ ] `--token-file <PATH>` (env `TUNNEL_TOKEN_FILE`)
- tests: `cli.rs::a_bare_share_names_the_modes`, `cli.rs::check_mode`, `cli.rs::error_messages_have_one_shape`, `cli.rs::exit_codes_of_flags_and_configuration`, `cli.rs::share_proxy_takes_a_unix_socket`; `src/main.rs`: `the_share_mode_follows_the_flags`, `the_idle_clock_starts_when_the_session_serves`
- live: L228 live-share.sh (QUIC, HTTP/2)

### `cfrs connect`

- [ ] command exists: Bridge a local socket to a remote WebSocket forward endpoint
  - [ ] `<REMOTE>` (required)
  - [ ] `-L, --local <LOCALS>` (required; repeatable)
  - [ ] `--run-for <RUN_FOR>`
  - [ ] `--no-check`
  - [ ] `--auth-user <USER>` (env `CFRS_AUTH_USER`)
  - [ ] `--auth-password-file <FILE>` (env `CFRS_AUTH_PASSWORD_FILE`)
  - [ ] `--detach`
  - [ ] `--name <NAME>`
  - [ ] `--ready-timeout <SECS>` (default `60`)
  - [ ] `--replace`
  - [ ] `--no-restart`
- tests: `cli.rs::bad_flag_values_are_usage_errors`, `cli.rs::exit_codes_of_flags_and_configuration`, `cli.rs::sigterm_is_a_clean_stop`, `connect.rs::connect_detach_is_in_ps_and_stops`, `connect.rs::connect_dials_through_the_proxy`, `connect.rs::connect_exits_69_when_the_remote_does_not_answer`, `connect.rs::connect_keeps_a_live_socket_and_other_files`, `connect.rs::connect_uses_resolve_pins`
- live: L219 live-throughput.sh (--forward WebSocket)

### `cfrs ports`

- [ ] command exists: List local TCP ports that are listening
  - [ ] `--json`
  - [ ] `--probe`
- tests: `cli.rs::an_empty_environment_works`, `cli.rs::invalid_values_are_refused`, `cli.rs::json_documents_have_the_schema_and_the_version`, `cli.rs::ports_json_is_one_object`
- live: -

### `cfrs bug-report`

- [ ] command exists: Print a text for a bug report: the version, cfrs status, the detached instances and the end of their logs, and the names of the variables that are set. Device IDs, tunnel IDs, tokens and credentials are hidden. No network unless --doctor
  - [ ] `--doctor`
- tests: none found
- live: -

### `cfrs completions`

- [ ] command exists: Print a completion script for a shell: bash, zsh, fish, elvish or powershell
  - [ ] `<SHELL>` (required; values `bash`, `elvish`, `fish`, `powershell`, `zsh`)
- tests: `cli.rs::bad_input_gives_usage_errors_not_panics`, `cli.rs::completion_scripts`
- live: -

### `cfrs update`

- [ ] command exists: Replace this binary with the binary of a release, after checking its signature (cosign, release.yml at the tag) and its SHA-256
  - [ ] `--check`
  - [ ] `--rollback`
  - [ ] `--force`
- tests: `cli.rs::exit_codes_of_flags_and_configuration`, `cli.rs::update_refuses_a_tag_with_a_path`, `egress.rs::a_proxy_host_that_does_not_resolve_is_an_error_not_a_crash`, `egress.rs::a_proxy_url_with_no_password_is_shown`
- live: L294 --check, --version, --rollback

### `cfrs qr`

- [ ] command exists: Print a QR code for a URL
  - [ ] `<URL>` (required)
- tests: none found
- live: -

### `cfrs demo`

- [ ] command exists: Test the full path: a built-in origin, a tunnel, a fetch of the URL
  - [ ] `--detach`
  - [ ] `--name <NAME>`
  - [ ] `--ready-timeout <SECS>` (default `60`)
  - [ ] `--replace`
  - [ ] `--no-restart`
  - [ ] `--service-url <SERVICE_URL>` (default `https://api.trycloudflare.com`)
  - [ ] `--user-agent <USER_AGENT>`
  - [ ] `--ha-connections <HA_CONNECTIONS>`
  - [ ] `--protocol <PROTOCOL>` (values `auto`, `quic`, `http2`, `h2`)
  - [ ] `--transport <TRANSPORT>` (default `auto`; values `auto`, `direct`, `warp`, `relay`)
  - [ ] `--relay <URL>` (default `https://tcp.ssh.relay.ajam.dev`; env `CFRS_RELAY`)
  - [ ] `--warp-identity <PATH>`
  - [ ] `--leg-failover <LEG_FAILOVER>` (default `staggered`; env `CFRS_LEG_FAILOVER`; values `staggered`, `serial`)
  - [ ] `--no-verify`
  - [ ] `--qr`
  - [ ] `--json`
  - [ ] `--run-for <RUN_FOR>`
  - [ ] `--auth-user <USER>` (env `CFRS_AUTH_USER`)
  - [ ] `--auth-password-file <FILE>` (env `CFRS_AUTH_PASSWORD_FILE`)
  - [ ] `--check`
  - [ ] `--exit-on-verify`
  - [ ] `--token <TOKEN>` (env `TUNNEL_TOKEN`)
  - [ ] `--token-file <PATH>` (env `TUNNEL_TOKEN_FILE`)
- tests: `cli.rs::check_mode`
- live: L94/L97/L100 QUIC, HTTP/2, --json; L171 UDP drop; L185 UDP refused; L199 CONNECT proxy and http+exec; L248 DNS; L283 --resolve pin; L356 --transport warp; L361 staggered legs; L381 --transport relay, --check; v6only/acceptance.sh

### `cfrs net`

- [ ] command exists: Userspace virtual networking (no kernel interfaces)
- tests: `cli.rs::bad_input_gives_usage_errors_not_panics`, `cli.rs::error_messages_have_one_shape`
- live: -

### `cfrs net demo`

- [ ] command exists: Prove the userspace TCP handshake + transfer in-process
- tests: none found
- live: -

### `cfrs net doctor`

- [ ] command exists: Probe what this host permits
  - [ ] `--json`
- tests: `cli.rs::doctor_tells_listen_from_bind`, `cli.rs::the_environment_is_checked_alike`
- live: L185 (UDP answered / refused)

### `cfrs net shim`

- [ ] command exists: Build (or locate) the LD_PRELOAD shim and print how to use it
  - [ ] `--out <OUT>`
  - [ ] `--log`
  - [ ] `--map-loopback`
  - [ ] `--json`
- tests: `shim_direct.rs::a_built_shim_needs_no_compiler_later`
- live: -

### `cfrs net addresses`

- [ ] command exists: Print the default virtual address plan
  - [ ] `--json`
- tests: `cli.rs::an_empty_environment_works`, `cli.rs::bad_input_gives_usage_errors_not_panics`, `cli.rs::error_messages_have_one_shape`
- live: -

### `cfrs net proxy`

- [ ] command exists: Run a SOCKS5 / HTTP CONNECT proxy into the virtual network
  - [ ] `--detach`
  - [ ] `--name <NAME>`
  - [ ] `--ready-timeout <SECS>` (default `60`)
  - [ ] `--replace`
  - [ ] `--no-restart`
  - [ ] `--listen <LISTEN>` (default `unix:/tmp/cfrsnet.socks`)
  - [ ] `--map <NAME=ADDR>` (repeatable)
  - [ ] `--forward <VIRT=REAL>` (repeatable)
  - [ ] `--port <PORT>` (default `80`)
  - [ ] `--run-for <RUN_FOR>`
  - [ ] `--switch <SWITCH>`
  - [ ] `--switch-token-file <PATH>`
  - [ ] `--address <ADDRESS>`
  - [ ] `--drop <DROP>` (default `0`)
  - [ ] `--duplicate <DUPLICATE>` (default `0`)
  - [ ] `--reorder <REORDER>` (default `0`)
  - [ ] `--seed <SEED>` (default `1`)
  - [ ] `--control <CONTROL>`
  - [ ] `--import <VIRT>` (repeatable)
- tests: `cli.rs::a_port_0_listener_prints_the_bound_port`, `cli.rs::a_tcp_switch_needs_a_token`, `cli.rs::the_fault_flags_need_a_switch_and_a_probability`, `cli.rs::the_socket_rule_of_net_and_relay`; `src/main.rs`: `the_pairs_of_listen_identity`
- live: -

### `cfrs net switch`

- [ ] command exists: Run a switch that connects stacks on this host and on other hosts
  - [ ] `--listen <LISTEN>` (default `unix:/tmp/cfrsnet.switch`)
  - [ ] `--switch-token-file <PATH>`
  - [ ] `--run-for <RUN_FOR>`
  - [ ] `--detach`
  - [ ] `--name <NAME>`
  - [ ] `--ready-timeout <SECS>` (default `60`)
  - [ ] `--replace`
  - [ ] `--no-restart`
- tests: `cli.rs::a_port_0_listener_prints_the_bound_port`, `cli.rs::a_tcp_switch_needs_a_token`, `cli.rs::autostart_from_an_instance_keeps_its_secrets_and_drops_detach_options`, `cli.rs::the_socket_rule_of_net_and_relay`, `detach.rs::a_child_goes_on_when_its_supervisor_is_killed`, `detach.rs::a_detached_instance_outlives_the_shell_that_started_it`, `detach.rs::a_failure_before_ready_gives_the_code_and_leaves_no_record`, `detach.rs::a_killed_instance_is_removed_and_can_start_again`, `detach.rs::a_named_foreground_process_is_in_ps_and_stops`, `detach.rs::a_named_foreground_process_keeps_no_secret_in_its_record`, `detach.rs::a_planned_end_is_not_restarted`, `detach.rs::a_second_start_with_the_same_name_is_the_same_instance`, `detach.rs::detach_options_need_detach_and_other_commands_refuse_it`, `detach.rs::detach_prints_only_the_ready_document_on_stdout`, `detach.rs::no_secret_in_the_arguments_of_the_child_or_in_the_record`, `detach.rs::stop_keeps_the_locks_of_a_live_instance_with_a_bad_record`, `detach.rs::stop_logs_and_wait`, `detach.rs::the_log_has_the_startup_lines_of_this_start`, `detach.rs::the_supervisor_starts_a_killed_child_again`, `detach.rs::two_starts_at_the_same_time_give_one_instance`
- live: -

### `cfrs net tailscale`

- [ ] command exists: Run a SOCKS5 / HTTP CONNECT front door to a tailnet through tailscaled
  - [ ] `--socket <SOCKET>` (default `/var/run/tailscale/tailscaled.sock`)
  - [ ] `--listen <LISTEN>` (default `unix:/tmp/cfrssocks.sock`)
  - [ ] `--port <PORT>` (default `80`)
  - [ ] `--run-for <RUN_FOR>`
- tests: `cli.rs::a_missing_upstream_is_named_at_start`
- live: -

### `cfrs net socksify`

- [ ] command exists: Build the LD_PRELOAD shim that sends tailnet connects to a front door
  - [ ] `--out <OUT>`
  - [ ] `--socket <PATH>` (default `/tmp/cfrssocks.sock`)
  - [ ] `--log`
  - [ ] `--json`
- tests: `cli.rs::socksify_takes_a_socket_path`
- live: -

### `cfrs net ts-shims`

- [ ] command exists: Write the user-table shims that Tailscale SSH needs on a host with no /etc/passwd
  - [ ] `--out <OUT>`
  - [ ] `--user <USER>`
  - [ ] `--uid <UID>`
  - [ ] `--gid <GID>`
  - [ ] `--shell <SHELL>`
  - [ ] `--json`
- tests: `cli.rs::ts_shims_skips_a_directory_open_to_others`
- live: -

### `cfrs warp`

- [ ] command exists: Cloudflare WARP client: registration, account, proxy, run
  (the flags below are global to each `warp` subcommand)
  - [ ] `--identity <PATH>`
  - [ ] `--ephemeral`
  - [ ] `--resolver <SPEC>` (repeatable; env `CFRS_WARP_RESOLVERS`)
  - [ ] `--device-name <NAME>` (env `CFRS_WARP_DEVICE_NAME`)
  - [ ] `--device-model <MODEL>` (env `CFRS_WARP_DEVICE_MODEL`)
  - [ ] `--device-locale <LOCALE>` (env `CFRS_WARP_DEVICE_LOCALE`)
  - [ ] `--fragment-client-hello <MODE>` (env `CFRS_WARP_FRAGMENT`)
  - [ ] `--fragment-size <MIN[-MAX]>` (env `CFRS_WARP_FRAGMENT_SIZE`)
  - [ ] `--cc <NAME>` (env `CFRS_WARP_CC`)
  - [ ] `--session-max-age <SECS>` (env `CFRS_WARP_SESSION_MAX_AGE`)
  - [ ] `--no-relay`
  - [ ] `--masque-endpoint <IP:PORT>`
  - [ ] `--masque-sni <NAME>`
  - [ ] `--masque-transport <PROTOCOL>` (env `CFRS_WARP_MASQUE_TRANSPORT`; values `h2`, `h3`)
  - [ ] `--transport <TRANSPORT>` (env `CFRS_WARP_TRANSPORT`; values `masque`, `wireguard`)
  - [ ] `--wireguard-endpoint <IP:PORT>` (env `CFRS_WARP_WG_ENDPOINT`)
  - [ ] `--carry <CARRY>` (env `CFRS_WARP_CARRY`; values `none`, `wg`)
  - [ ] `--carry-endpoint <IP:PORT>` (env `CFRS_WARP_CARRY_ENDPOINT`)
- tests: `cli.rs::bad_input_gives_usage_errors_not_panics`, `cli.rs::the_log_holds_no_secret`, `cli.rs::warp_status_registers_no_device`
- live: -

### `cfrs warp register`

- [ ] command exists: Register a device (or load the saved one) and print it
- tests: none found
- live: L446; L463 (second API host)

### `cfrs warp status`

- [ ] command exists: Print the device and the account (type, WARP+ state, quota)
  - [ ] `--json`
- tests: `docs.rs::the_readme_does_not_call_warp_flags_global`; `src/main.rs`: `warp_license_and_status_fields`
- live: L446; L463

### `cfrs warp license`

- [ ] command exists: Attach a WARP+ license key to the device
  - [ ] `<KEY>` (required)
- tests: none found; `src/main.rs`: `warp_license_and_status_fields`, `license_and_expose_classes`
- live: -

### `cfrs warp rotate`

- [ ] command exists: Make a new MASQUE key and enrol it. The old key stops working
- tests: none found
- live: -

### `cfrs warp delete`

- [ ] command exists: Remove the device from the WARP service and delete the saved file
- tests: none found
- live: L463; L924 (cleanup); live-batch2.sh

### `cfrs warp probe`

- [ ] command exists: Open the tunnel and test TCP connects through it. Exit 69 when a target fails
  - [ ] `--target <TARGET>` (repeatable)
- tests: `cli.rs::the_environment_is_checked_alike`; `src/main.rs`: `probe_targets_take_a_name_or_an_address`
- live: L446; L510 (through the relay); live-batch2.sh (--fragment-client-hello, --masque-transport h3, --transport wireguard)

### `cfrs warp exit`

- [ ] command exists: Open the tunnel and print its exit: the data center (colo), the country and the address that a destination sees (from http://1.1.1.1/cdn-cgi/trace), and the IPv6 egress address (the trace at 2606:4700:4700::1111, else the TXT of whoami.cloudflare). Exit 69 when there is no answer
  - [ ] `--json`
  - [ ] `--no-ipv6`
- tests: none found
- live: live-batch2.sh (--json; --carry wg --transport)

### `cfrs warp export`

- [ ] command exists: Print a WireGuard config of a new WARP device (wg-quick or JSON), for other clients. The device and its private key are in warp-wg.json of the state directory, not in warp.json. Its data path is WireGuard on UDP (port 2408), not MASQUE on TCP 443. The output holds the private key: a terminal is refused with no --out (--out - prints it), and a redirected file becomes mode 0600
  - [ ] `--format <FORMAT>` (default `wg-quick`; values `wg-quick`, `json`)
  - [ ] `--out <FILE>`
  - [ ] `--export-identity <FILE>`
  - [ ] `--endpoint <HOST:PORT>`
  - [ ] `--keepalive <SECS>` (default `25`)
  - [ ] `--new`
  - [ ] `--delete`
- tests: none found
- live: live-batch2.sh (--format json, --export-identity, --delete)

### `cfrs warp scan`

- [ ] command exists: Measure front doors of WARP: the TCP connect and the TLS handshake with the pinned key, for each --candidate and the front doors of the device record. The fastest goes first. Exit 69 when none answers
  - [ ] `--candidate <IP[:PORT]>` (repeatable)
  - [ ] `--timeout-ms <MS>` (default `3000`)
  - [ ] `--json`
- tests: `cli.rs::invalid_values_are_refused`; `src/main.rs`: `the_front_doors_of_a_scan`
- live: live-batch2.sh (--candidate --json)

### `cfrs warp forward`

- [ ] command exists: Forward local listeners through WARP (as ssh -L): each connection to LISTEN goes through the tunnel to HOST:PORT
  - [ ] `-L, --local <LISTEN=HOST:PORT>` (required; repeatable; env `CFRS_WARP_FORWARD`)
  - [ ] `--strict`
  - [ ] `--max-connections <N>` (default `32`)
  - [ ] `--run-for <RUN_FOR>`
  - [ ] `--detach`
  - [ ] `--name <NAME>`
  - [ ] `--ready-timeout <SECS>` (default `60`)
  - [ ] `--replace`
  - [ ] `--no-restart`
- tests: none found
- live: live-batch2.sh (-L --run-for)

### `cfrs warp proxy`

- [ ] command exists: Run a local SOCKS5 and HTTP CONNECT proxy whose traffic goes through WARP (the proxy mode of the WARP client)
  - [ ] `--listen <LISTEN>` (repeatable; default `tcp://127.0.0.1:40000`)
  - [ ] `--strict`
  - [ ] `--max-connections <N>` (default `0`)
  - [ ] `--dns <ADDR>`
  - [ ] `--proxy-user <USER>` (env `CFRS_PROXY_USER`)
  - [ ] `--proxy-password-file <FILE>` (env `CFRS_PROXY_PASSWORD_FILE`)
  - [ ] `-r, --rule <KIND:VALUE=ACTION>` (repeatable; env `CFRS_WARP_RULES`)
  - [ ] `--l4` (env `CFRS_WARP_L4`)
  - [ ] `--l4-sni <NAME>` (default `consumer-masque-proxy.cloudflareclient.com`)
  - [ ] `--listen-identity <LISTEN=PATH>` (repeatable)
  - [ ] `--rules-file <FILE>` (env `CFRS_WARP_RULES_FILE`)
  - [ ] `--rule-default <ACTION>` (default `tunnel`)
  - [ ] `--check`
  - [ ] `--run-for <RUN_FOR>`
  - [ ] `--detach`
  - [ ] `--name <NAME>`
  - [ ] `--ready-timeout <SECS>` (default `60`)
  - [ ] `--replace`
  - [ ] `--no-restart`
- tests: none found; `src/main.rs`: `the_pairs_of_listen_identity`
- live: L487 (exit 69); L772 --listen --dns, SOCKS5 UDP, IPv6, TCP burst vs beta.6; live-batch2.sh (rules, nested --proxy, --cc, h3, --l4 --l4-sni, wireguard)

### `cfrs warp up`

- [ ] command exists: Start WARP for this sandbox, in the background: a detached warp proxy on 127.0.0.1:PORT and on a unix socket, and an env file with the proxy variables. Later shells join it with `eval "$(cfrs warp env)"`, `cfrs warp exec -- CMD`, `cfrs warp shell`, or --persist
  - [ ] `--port <PORT>` (default `40000`)
  - [ ] `--persist`
  - [ ] `--env-d`
  - [ ] `--ready-timeout <READY_TIMEOUT>` (default `90`)
  - [ ] `--tun`
  - [ ] `--replace`
  - [ ] `--dns <ADDR>`
  - [ ] `--proxy-user <USER>` (env `CFRS_PROXY_USER`)
  - [ ] `--proxy-password-file <FILE>` (env `CFRS_PROXY_PASSWORD_FILE`)
- tests: none found; `src/main.rs`: `warp_up_tun_keeps_the_front_door`, `the_warp_up_summary_starts_with_what_works`, `the_warp_proxy_of_warp_up_parses`
- live: L487 (--tun exit 69); L525 (TCP listener refused); L549 (--persist, re-up keeps pid, one-root CA)

### `cfrs warp down`

- [ ] command exists: Stop what cfrs warp up started, and remove its env file and its block in ~/.bashrc and ~/.profile
- tests: none found
- live: L525; L549

### `cfrs warp env`

- [ ] command exists: Print the proxy variables of the running cfrs warp up, for `eval "$(cfrs warp env)"`. Exit 69 with no output when warp up has no TCP listener (no proxy variables)
- tests: `cli.rs::warp_env_with_no_proxy_variables_exits_69`
- live: L525; L549

### `cfrs warp exec`

- [ ] command exists: Run a program under the pod of the running cfrs warp up: TCP, DNS and UDP go through WARP, also for static binaries
  - [ ] `-r, --rule <SPEC>` (repeatable)
  - [ ] `<PROGRAM>...` (required; repeatable)
- tests: none found
- live: L525; L549

### `cfrs warp shell`

- [ ] command exists: Run $SHELL under the pod of the running cfrs warp up. When it does not run, the shell starts as it is (with the proxy variables when the env file is there)
- tests: none found
- live: -

### `cfrs warp nc`

- [ ] command exists: A byte pipe from stdin and stdout to HOST:PORT through WARP, for `ssh -o ProxyCommand='cfrs warp nc %h %p'` and git over SSH. It uses the running cfrs warp up, else a WARP session of its own
  - [ ] `<HOST>` (required)
  - [ ] `<PORT>` (required)
  - [ ] `--via-relay`
  - [ ] `-u, --udp`
  - [ ] `--idle <SECS>`
  - [ ] `-N, --shutdown`
- tests: none found
- live: L446 (-u 1.1.1.1 53); L549

### `cfrs warp ssh-config`

- [ ] command exists: Print an SSH config block and GIT_SSH_COMMAND that use cfrs warp nc. With --write, --remove or --check: own the block in the SSH config file, between two marker lines
  - [ ] `--host <HOST>`
  - [ ] `--write`
  - [ ] `--remove`
  - [ ] `--check`
  - [ ] `--config <FILE>` (default `~/.ssh/config`)
- tests: `cli.rs::root_writes_no_file_in_the_home_of_another_user`, `cli.rs::ssh_config_refuses_a_host_with_a_newline_or_a_space`, `cli.rs::warp_ssh_config_owns_its_block`
- live: L549 (--host, --write, --check, --remove, --config)

### `cfrs warp tun`

- [ ] command exists: Make a TUN interface whose packets go through WARP. Needs CAP_NET_ADMIN and /dev/net/tun. Routes are not changed
  - [ ] `--interface <INTERFACE>` (default `cfrs0`)
  - [ ] `--default-route`
  - [ ] `--detach`
  - [ ] `--name <NAME>`
  - [ ] `--ready-timeout <SECS>` (default `60`)
  - [ ] `--replace`
  - [ ] `--no-restart`
- tests: none found
- live: L487 (exit 69); L684 --default-route (root); L711 no default route

### `cfrs warp run`

- [ ] command exists: Run a program with all its traffic sent through WARP. No root and no TUN device are necessary (pod-netns)
  - [ ] `--backend <BACKEND>` (default `auto`)
  - [ ] `-r, --rule <SPEC>` (repeatable)
  - [ ] `--keep-proxy-env`
  - [ ] `--inbound-dir <DIR>`
  - [ ] `<PROGRAM>...` (required; repeatable)
- tests: none found
- live: L656 --backend netns-raw; L753 --backend seccomp (TCP, UDP)

### `cfrs relay`

- [ ] command exists: Inbound access to this host through the WebSocket relay (--relay): pair, run a node for a local port, connect as the operator
  - [ ] `--relay <URL>` (default `https://tcp.ssh.relay.ajam.dev`; env `CFRS_RELAY`)
- tests: none found
- live: -

### `cfrs relay pair`

- [ ] command exists: Ask the relay for a pair: a name, a node token (kept in a file of mode 0600 in the state directory) and a connect token for the operator. A pair lasts at most 72 h
  - [ ] `--json`
- tests: none found
- live: L398 --json

### `cfrs relay node`

- [ ] command exists: Hold the node socket of a pair, and connect each session of an operator to a local service. A lost socket is opened again
  - [ ] `<PAIR>`
  - [ ] `--to <TARGET>` (required)
  - [ ] `--detach`
  - [ ] `--name <NAME>`
  - [ ] `--ready-timeout <SECS>` (default `60`)
  - [ ] `--replace`
  - [ ] `--no-restart`
- tests: none found
- live: L398 --to --detach --name

### `cfrs relay connect`

- [ ] command exists: Open a session to a node and copy stdin and stdout (an SSH ProxyCommand), or each connection of --listen
  - [ ] `<NAME>` (required)
  - [ ] `--token <TOKEN>` (env `CFRS_RELAY_CONNECT_TOKEN`)
  - [ ] `--token-file <PATH>`
  - [ ] `--listen <LISTEN>`
- tests: `cli.rs::exit_codes_of_flags_and_configuration`
- live: L398 (ProxyCommand, 2 parallel sessions, banner)

### `cfrs relay stop`

- [ ] command exists: Stop a node and its sessions at the relay (POST /v1/stop), and remove the local pair file
  - [ ] `<NAME>` (required)
- tests: `cli.rs::exit_codes_of_flags_and_configuration`
- live: L398

### `cfrs pod`

- [ ] command exists: Run a program with all its traffic sent through a proxy (pod-netns)
  - [ ] `<ARGS>...` (repeatable)
- tests: `cli.rs::a_global_flag_before_pod_does_not_panic`, `cli.rs::a_missing_upstream_is_named_at_start`; `src/main.rs`: `the_pod_keeps_its_double_dash`
- live: -

### `cfrs man`

- [ ] command exists: Show the manual, generated from this binary
  - [ ] `<SECTION>...` (repeatable)
  - [ ] `--no-pager`
  - [ ] `--roff`
  - [ ] `--json`
- tests: `cli.rs::an_empty_environment_works`, `cli.rs::the_listen_defaults_agree_with_the_manual`, `cli.rs::the_man_page_names_each_flag`
- live: -

### `cfrs status`

- [ ] command exists: Print one line of JSON about this host. It opens no connection
  - [ ] `--json`
- tests: `cli.rs::a_full_stdout_is_no_panic`, `cli.rs::an_empty_environment_works`, `cli.rs::autostart_with_cron_and_with_nothing`, `cli.rs::bad_input_gives_usage_errors_not_panics`, `cli.rs::error_messages_have_one_shape`, `cli.rs::exit_codes_of_flags_and_configuration`, `cli.rs::invalid_values_are_refused`, `cli.rs::json_documents_have_the_schema_and_the_version`, `cli.rs::root_writes_no_file_in_the_home_of_another_user`, `cli.rs::the_environment_is_checked_alike`, `cli.rs::the_read_commands_make_no_run_directory`, `cli.rs::tunnel_tcp_takes_the_scheme_and_warns`, `cli.rs::warp_status_registers_no_device`, `detach.rs::detach_options_need_detach_and_other_commands_refuse_it`, `doctor.rs::a_proxy_that_refuses_7844_and_terminates_tls`
- live: -

### `cfrs doctor`

- [ ] command exists: Test the path from this host to the edge: the proxy, TCP and TLS to the APIs, the edge (7844) and MASQUE (443), and UDP 7844. Exit 0 when at least one leg (quic, http2, quic+warp) can work, 1 when none can
  - [ ] `--json`
  - [ ] `--agent`
  - [ ] `--samples <SAMPLES>` (default `9`)
  - [ ] `--timeout <TIMEOUT>` (default `3`)
- tests: `cli.rs::the_environment_is_checked_alike`, `doctor.rs::a_proxy_that_refuses_7844_and_terminates_tls`
- live: L78 --json legs/roads/clock/paths; L361 --samples; L549 --agent --json; v6only

### `cfrs autostart`

- [ ] command exists: Start a cfrs command at boot, with no root: a systemd user unit (it stops at logout unless linger is on), else an @reboot line in the crontab
- tests: none found
- live: -

### `cfrs autostart add`

- [ ] command exists: Add an entry that runs `cfrs ARGS`. The token and a proxy password go to a private env file (mode 0600), not to the unit, the crontab or the command line. Exit 69 when this host has no systemd user manager and no crontab
  - [ ] `<NAME>` (required)
  - [ ] `<ARGS>...` (repeatable)
  - [ ] `--from <INSTANCE>`
- tests: `cli.rs::autostart_from_an_instance_keeps_its_secrets_and_drops_detach_options`, `cli.rs::autostart_with_cron_and_with_nothing`, `cli.rs::exit_codes_of_flags_and_configuration`
- live: L317 (systemd user unit, secrets kept out)

### `cfrs autostart remove`

- [ ] command exists: Remove an entry: its unit or its crontab line, and its files. Other units and crontab lines stay as they are
  - [ ] `<NAME>` (required)
- tests: `cli.rs::autostart_with_cron_and_with_nothing`
- live: L317

### `cfrs autostart list`

- [ ] command exists: List the entries
- tests: `cli.rs::autostart_with_cron_and_with_nothing`
- live: -

### `cfrs autostart run`

- [ ] command exists: Run an entry in the place of this process: the unit and the crontab line call this. It reads NAME.args and NAME.env in DIR
  - [ ] `<NAME>` (required)
  - [ ] `--dir <DIR>` (required)
- tests: none found
- live: -

### `cfrs agent`

- [ ] command exists: One command for a sandbox with basic networking: test what works, start WARP when it is needed, expose ports, and print what works now and the commands to use
- tests: none found
- live: -

### `cfrs agent up`

- [ ] command exists: Test the host (cfrs doctor --agent), start cfrs warp up when direct networking does not do each task, start a detached quick tunnel for each --expose PORT, and print one JSON document
  - [ ] `--persist`
  - [ ] `--expose <PORT>` (repeatable)
  - [ ] `--port <PORT>` (default `40000`)
  - [ ] `--warp`
- tests: `cli.rs::the_environment_is_checked_alike`; `src/main.rs`: `the_agent_commands_follow_the_listeners`, `license_and_expose_classes`
- live: L623 (--expose x2, mode warp, works)

### `cfrs agent down`

- [ ] command exists: Stop what cfrs agent up started and put back each change
- tests: none found
- live: L623

### `cfrs agent status`

- [ ] command exists: Print the state: the instances, cfrs warp up, and the doctor
- tests: none found
- live: -

### `cfrs ps`

- [ ] command exists: List the instances that run in the background (--detach)
  - [ ] `--json`
- tests: `cli.rs::json_documents_have_the_schema_and_the_version`, `cli.rs::the_read_commands_make_no_run_directory`, `connect.rs::connect_detach_is_in_ps_and_stops`, `detach.rs::a_named_foreground_process_keeps_no_secret_in_its_record`
- live: L132; L398; L623

### `cfrs stop`

- [ ] command exists: Stop a detached instance: SIGTERM, then SIGKILL after --timeout
  - [ ] `<NAME>`
  - [ ] `--all`
  - [ ] `--timeout <TIMEOUT>` (default `10`)
- tests: `cli.rs::autostart_from_an_instance_keeps_its_secrets_and_drops_detach_options`, `cli.rs::error_messages_have_one_shape`, `cli.rs::the_read_commands_make_no_run_directory`, `connect.rs::connect_detach_is_in_ps_and_stops`, `detach.rs::a_child_goes_on_when_its_supervisor_is_killed`, `detach.rs::a_named_foreground_process_is_in_ps_and_stops`, `detach.rs::a_named_foreground_process_keeps_no_secret_in_its_record`, `detach.rs::logs_stop_and_wait_refuse_a_name_that_leaves_the_run_directory`, `detach.rs::stop_keeps_the_locks_of_a_live_instance_with_a_bad_record`, `detach.rs::stop_logs_and_wait`, `detach.rs::the_log_has_the_startup_lines_of_this_start`, `detach.rs::the_supervisor_starts_a_killed_child_again`
- live: L132; L152; L398; L684; L711

### `cfrs logs`

- [ ] command exists: Print the log of a detached instance
  - [ ] `<NAME>` (required)
  - [ ] `-f, --follow`
  - [ ] `-n, --lines <LINES>`
- tests: `cli.rs::the_read_commands_make_no_run_directory`, `detach.rs::a_named_foreground_process_is_in_ps_and_stops`, `detach.rs::logs_stop_and_wait_refuse_a_name_that_leaves_the_run_directory`, `detach.rs::stop_logs_and_wait`, `detach.rs::the_log_has_the_startup_lines_of_this_start`
- live: L132; L684

### `cfrs wait`

- [ ] command exists: Wait until a detached instance is ready, and print its ready document
  - [ ] `<NAME>` (required)
  - [ ] `--timeout <TIMEOUT>` (default `60`)
- tests: `cli.rs::the_read_commands_make_no_run_directory`, `detach.rs::a_named_foreground_process_is_in_ps_and_stops`, `detach.rs::logs_stop_and_wait_refuse_a_name_that_leaves_the_run_directory`, `detach.rs::stop_logs_and_wait`, `detach.rs::wait_for_a_name_that_never_existed_says_so`
- live: -

## 4. `pod-netns` CLI (also `cfrs pod`)

Hand-written parser: `crates/pod-netns/src/cli.rs` `parse_args`.

- [ ] `pod-netns [OPTIONS] -- PROGRAM [ARGS]...` runs the program; exit code of the program
- [ ] `pod-netns doctor [--json]`: what the host permits; exit 3 when no backend can run (no `schema` key, own words `ok`/`no`/`available`)
- [ ] `pod-netns --serve LISTEN -x PROXY`: SOCKS5, HTTP CONNECT and UDP ASSOCIATE on `unix:/path` or `tcp://host:port`
- [ ] `-x, --proxy SPEC` repeatable, chains: `socks5://[user:pass@]host:port`, `http://...`, `socks5://unix:/path`, `http://unix:/path`, `tailscale:/path/to/tailscaled.sock`; default `ALL_PROXY`, `all_proxy`, `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy` (first that parses)
- [ ] `-r, --rule SPEC`: `domain:NAME=PROXY`, `domain:.suffix=PROXY`, `cidr:NET=PROXY`, `cidr:NET=direct`; first match wins; seccomp: 127.0.0.0/8 direct
- [ ] `--map NAME=ADDR` repeatable
- [ ] `--keep-proxy-env`
- [ ] `--backend auto|netns|seccomp`
- [ ] `--prefer-udp`
- [ ] `--inbound-dir DIR` (default `$XDG_RUNTIME_DIR/pod-netns-inbound`, else `$TMPDIR/pod-netns-inbound-UID`; owner and mode checks)
- [ ] `-v, --verbose`, `-V, --version` (`pod-netns VERSION (COMMIT)`), `-h, --help`
- [ ] usage errors exit 64 (also no proxy at all); 3 when no backend can run
- [ ] program name in messages: `cfrs pod` when called from cfrs (`set_program_name`)
- [ ] library: `pod_netns::raw` (the `netns-raw` backend of `cfrs warp run --backend netns-raw`), `socks`, `tailscale`, `upstream`, `dns`, `listen`, `QUIET_VARIABLE`, `main_with_args`, `usage`, `usage_for`

Pinned by: `crates/pod-netns/tests/usage.rs` (3), `tests/seccomp.rs` (30),
`tests/raw.rs` (1), unit tests in `crates/pod-netns/src` (43), `tests/cli.rs`
(`a_global_flag_before_pod_does_not_panic`, `a_missing_upstream_is_named_at_start`),
live L656 and L753 (`warp run --backend netns-raw|seccomp`), `scripts/test_in_box.sh`.

## 5. Environment variables (`src/manual/facts.rs` `ENVIRONMENT`)

Pinned by `manual::facts` tests `each_variable_in_the_source_is_in_the_manual`
and `each_variable_in_the_manual_is_read_by_the_source` (they scan `src/`
for `var("`, `var_os("`, `env = "` and `*_VARIABLE` constants: a crate
split must widen the scan to each crate), and `tests/cli.rs::the_environment_is_checked_alike`.
A rename to `PODNET_*` needs a ruling: keep the `CFRS_*` names as aliases or not.

- [ ] `HTTPS_PROXY` / `https_proxy` / `ALL_PROXY` / `all_proxy`: tunnel, warp, edge discovery, pod
- [ ] `NO_PROXY` / `no_proxy`: all commands
- [ ] `CFRS_RESOLVE`: all commands
- [ ] `HTTP_PROXY` / `http_proxy`: pod
- [ ] `TUNNEL_TOKEN`: tunnel, serve, share, demo
- [ ] `TUNNEL_TOKEN_FILE`: tunnel, serve, share, demo
- [ ] `SSL_CERT_FILE`: all commands
- [ ] `CFRS_STATE_DIR`: warp, tunnel --transport warp
- [ ] `XDG_STATE_HOME` / `HOME` / `XDG_RUNTIME_DIR` / `TMPDIR`: warp, net shim, net socksify, autostart
- [ ] `XDG_CONFIG_HOME`: autostart
- [ ] `CFRS_LEG_FAILOVER`: tunnel, serve, share, demo
- [ ] `NO_COLOR`: all commands
- [ ] `CFRS_EDGE`: tunnel, serve, share, demo, doctor, net doctor
- [ ] `CFRS_PROXY`: all commands
- [ ] `CFRS_WARP_SHELL`: warp shell, the block of warp up --persist
- [ ] `SHELL`: warp shell
- [ ] `CFRS_RUN_DIR`: --detach, ps, stop, logs, wait
- [ ] `CFRS_DETACH_NAME` / `CFRS_DETACH_HASH` / `CFRS_DETACH_COMMAND` / `CFRS_DETACH_SUPERVISED` / `CFRS_DETACH_READY_TIMEOUT`: --detach
- [ ] `CFRS_RELAY`: tunnel, serve, share, demo, relay
- [ ] `CFRS_REPO`: update
- [ ] `CFRS_FOREIGN_HOME`: the state directory, warp ssh-config --write, warp up --persist and --env-d, autostart
- [ ] `CFRS_AUTH_USER` / `CFRS_AUTH_PASSWORD_FILE`: tunnel, serve, share, demo, connect
- [ ] `CFRS_RELAY_TOKEN`: tunnel, serve, share, demo
- [ ] `CFRS_RELAY_CONNECT_TOKEN`: relay connect
- [ ] `POD_NETNS_TEST_MEM`: pod (tests only)
- [ ] `CFRS_WARP_API`: warp (each command that calls the WARP API)
- [ ] `CFRS_WARP_TCP_BURST`: warp proxy, warp run, warp up, agent up
- [ ] `CFRS_WARP_MASQUE_TRANSPORT`: warp (each command that opens a MASQUE session), warp up (its proxy)
- [ ] `CFRS_WARP_TRANSPORT` / `CFRS_WARP_WG_ENDPOINT`: warp (each command that opens a session), warp up (its proxy)
- [ ] `CFRS_WARP_CARRY` / `CFRS_WARP_CARRY_ENDPOINT`: warp (each command with a userspace stack), warp up (its proxy)
- [ ] `CFRS_WARP_L4_FORM`: warp proxy --l4
- [ ] `CFRS_WARP_L4`: warp proxy
- [ ] `CFRS_WARP_SESSION_MAX_AGE`: warp proxy, warp forward, warp run, warp up
- [ ] `CFRS_WARP_CC`: warp (each command with a userspace stack), warp up (its proxy), tunnel --transport warp
- [ ] `CFRS_WARP_NO_CHECK`: warp proxy, warp run, warp up, warp probe, warp exit, warp nc, agent up
- [ ] `POD_NETNS_QUIET`: pod, warp exec, warp shell, warp run
- [ ] `CFRS_PROXY_USER` / `CFRS_PROXY_PASSWORD_FILE`: warp proxy, warp up
- [ ] `CFRS_WARP_DEVICE_NAME` / `CFRS_WARP_DEVICE_MODEL` / `CFRS_WARP_DEVICE_LOCALE`: warp (each command that registers a device), tunnel --transport warp
- [ ] `CFRS_WARP_FRAGMENT` / `CFRS_WARP_FRAGMENT_SIZE`: warp (each command that opens a MASQUE session), warp up (its proxy)
- [ ] `CFRS_WARP_RULES` / `CFRS_WARP_RULES_FILE`: warp proxy, warp up (its proxy reads them)
- [ ] `CFRS_WARP_FORWARD`: warp forward
- [ ] `CFRS_WARP_RESOLVERS`: warp proxy, warp up, warp run, warp tun, warp probe, warp nc, tunnel --transport warp
- [ ] `CFRS_UDP`: tunnel, serve, share, demo, doctor
- [ ] `CFRS_ERROR_PROGRAM`: all commands
- [ ] `RUST_LOG`: all commands
- [ ] `CFRS_DEBUG`: serve (SSH relay)
- [ ] `PAGER` / `TERM` / `LESS` / `LINES`: man
- [ ] `PATH`: pod, man, net shim
- [ ] `CC`: net shim, net socksify, net ts-shims
- [ ] `USER`: net ts-shims
- [ ] `LD_PRELOAD`: net shim, net socksify
- [ ] `CFRS_SWITCH_TOKEN`: net switch, net proxy --switch
- [ ] `CFRSNET_SHIM` / `CFRSSOCKS_SHIM`: net shim, net socksify
- [ ] `CFRSNET_LOG` / `CFRSNET_MAP_LOOPBACK` / `CFRSNET_LOCAL_ADDR` / `CFRSNET_PREFIX` / `CFRSNET_HOSTS` / `CFRSNET_CONTROL` / `CFRSNET_MAX_FDS`: libcfrsnet.so
- [ ] `CFRSSOCKS_PROXY` / `CFRSSOCKS_LOG` / `CFRSSOCKS_ALL` / `CFRSSOCKS_MAX_FDS`: libcfrssocks.so
- [ ] `SANDHOME_PASSWD` / `UNIXSOCKD_LOG`: net ts-shims, unixsockd
- [ ] `CFRS_BUILD_COMMIT`: the build
- [ ] `SOURCE_DATE_EPOCH`: the build

## 6. Files

- [ ] `<state directory>/warp.json`
- [ ] `cfrs-ca.pem (beside the binary)`
- [ ] `/etc/ssl/certs/ca-certificates.crt`
- [ ] `config.yml (--config)`
- [ ] `~/.cloudflared/<tunnel-id>.json (--credentials-file)`
- [ ] `/tmp/cfrsnet.socks`
- [ ] `/tmp/cfrsnet.switch`
- [ ] `/tmp/cfrssocks.sock`
- [ ] `/tmp/cfrs-warp-<pid>.sock`
- [ ] `$XDG_RUNTIME_DIR/pod-netns-inbound/<port>.sock, else $TMPDIR/pod-netns-inbound-<uid>/<port>.sock`
- [ ] `$TMPDIR/cfrsnet, $TMPDIR/cfrssocks, $TMPDIR/cfrs-ts-shims`
- [ ] `<state directory>/warp-carry.json`, `warp-wg.json` (export), the door cache of WARP (`{"schema":1,"door","at"}`)
- [ ] `<state directory>/relay-pool-HOST.json`, `relay-token-HOST.json`, relay pair files (mode 0600)
- [ ] `<state directory>/autostart/*.env` (mode 0600), systemd user unit `cfrs-NAME`, crontab `@reboot` line
- [ ] run directory (`CFRS_RUN_DIR`): one record and one log for each instance (`ps`, `logs`, `stop`, `wait`)
- [ ] marker blocks: `>>> cfrs warp up >>>` in `~/.profile` and `~/.bashrc` (`warp up --persist`), the block of `warp ssh-config --write`
- [ ] the shims built in `$TMPDIR/cfrsnet`, `$TMPDIR/cfrssocks`, `$TMPDIR/cfrs-ts-shims` (`libcfrsnet.so`, `libcfrssocks.so`)

A rename changes the state directory (`$XDG_STATE_HOME/cfrs`) and these names:
decide migration (read the old directory) before the first podnet release.

## 7. Exit codes (`src/exit.rs` `TABLE`)

- [ ] 0 `success`
- [ ] 1 `failure`
- [ ] 3 `no-backend`
- [ ] 64 `usage`
- [ ] 69 `unavailable`
- [ ] 75 `tempfail`
- [ ] 78 `config`
- [ ] 124 `timeout`

Pinned by `tests/cli.rs` (`a_usage_error_exits_64`, `a_bad_configuration_exits_78`,
`exit_codes_of_flags_and_configuration`, `bad_credentials_exit_78`), `exit.rs` unit
tests, `tests/detach.rs` (124 of `wait --timeout`, 75), live L487 (69).

## 8. JSON documents

Rule (E3): each JSON document on stdout has `schema` (1) and `cfrs` (the version)
through `status::stamped` (`tests/cli.rs::json_documents_have_the_schema_and_the_version`
checks `ps --json`, `ports --json`, `status`). A rename of the key `cfrs` is breaking.

| Done | Command | Document | Pinned by |
| --- | --- | --- | --- |
| [ ] | `cfrs status` | `status::document`: os, arch, proxy, edge_override, warp_identity, tls_roots, ... | `tests/cli.rs` (json_documents..., status_names_the_kind...), `status.rs` tests |
| [ ] | `cfrs ports --json [--probe]` | `{"ports": [...], "unreachable"?}` | `tests/cli.rs::ports_json_is_one_object` |
| [ ] | `cfrs ps --json` | `{"instances": [...], "dir"}`; each instance: name, state, ready, pid ... | `tests/cli.rs`, `tests/detach.rs`, live L132/L398/L623 |
| [ ] | `cfrs wait NAME` | the ready record of the instance | `tests/detach.rs::stop_logs_and_wait` |
| [ ] | `--detach` (parent) | the ready document with `"event": "detached"` (`detach.rs`) | `tests/detach.rs`, live L132/L684 |
| [ ] | `tunnel`/`serve`/`share`/`demo --json` | JSON lines: `{"event":"ready", url, leg, tunnel_id, ...}` (`announce`), `{"event":"verified", url, dns}` | live L100/L113/L317; `main.rs::a_sigterm_after_the_ready_line...` |
| [ ] | `tunnel`/`serve`/`share`/`demo --detach` | `tunnel_doc` (url, verified, ...) | live L132/L152 |
| [ ] | `serve --local ADDR --json` | `{"event":"ready", url, listen}` | `tests/cli.rs::serve_local_serves_files_*` |
| [ ] | `tunnel --check --json` | `preflight` report (stamped) | `tests/cli.rs::check_mode` |
| [ ] | `connect --detach` | ready document (listen, remote) | `tests/connect.rs::connect_detach_is_in_ps_and_stops` |
| [ ] | `doctor --json` | `doctor::Report::to_json`: legs, roads, clock, paths (dns, tls), proxy, verdict | `tests/doctor.rs`, live L78/L361 |
| [ ] | `doctor --agent --json` | `agent.rs`: rows (task, direct, warp), warp_up | `agent.rs` tests, live L549 |
| [ ] | `agent up` / `agent status` | `{"event":"agent", mode, exposed[], works{}, ...}` (stamped) | `main.rs::license_and_expose_classes`, live L623 |
| [ ] | `net doctor --json` | `{"probes": [...], "verdict"}` (stamped) | `tests/cli.rs::doctor_tells_listen_from_bind` |
| [ ] | `net addresses --json` | the addresses of a subnet | `tests/cli.rs::an_empty_environment_works` |
| [ ] | `net shim --json`, `net socksify --json`, `net ts-shims --json` | the environment as one object | `tests/shim_*.rs`, `tests/cli.rs::socksify_takes_a_socket_path` |
| [ ] | `net proxy` / `net switch` (ready) | `{"listen": ...}` (`listen_doc`) | `tests/detach.rs`, `tests/cli.rs::a_port_0_listener_prints_the_bound_port` |
| [ ] | `warp status --json` | the account record (pretty) | `main.rs::warp_license_and_status_fields`, live L446 |
| [ ] | `warp exit --json` | `warp::exit::Exit::to_json` (colo, loc, ip, ipv6, warp) | live-batch2.sh |
| [ ] | `warp scan --json` | `{"doors": [...]}` | `main.rs::the_front_doors_of_a_scan`, live-batch2.sh |
| [ ] | `warp export --format json` | `warp::export` (WireGuard peer, keys, endpoint) | `warp/export.rs` tests, live-batch2.sh |
| [ ] | `warp proxy`, `warp forward`, `warp tun` (ready) | ready documents (listen, default_route, ...) | live L684/L711 |
| [ ] | `warp up` | `warp::up::start`: name, pid, port, tcp, persist, env_d, ... | `warp/up.rs` tests, live L525/L549 |
| [ ] | `relay pair --json` | the pair with the connect token (not the node token) | live L398 |
| [ ] | `relay node` (ready) | `relay_reverse::node_ready` (pair, target) | `tests/relay_reverse.rs`, live L398 |
| [ ] | `man --json` | `manual::model::Manual`: name, version, commands[], pod_usage, environment, files, exit_status, examples | `manual` tests, `tests/cli.rs::the_listen_defaults_agree_with_the_manual` |
| [ ] | `--log-format json` | one JSON object per log line; the last error line is JSON too (`error_json`) | `tests/cli.rs::log_format_json_gives_json_lines_only` |
| [ ] | `CFRS_ERROR_PROGRAM` stdin | `report::document`: schema, cfrs, os, arch, command, exit, error[], hop, refusal (status, code, retry_after_s), messages[] | `report.rs` tests, `tests/cli.rs::the_failure_report_has_the_error_once` |
| [ ] | `pod-netns doctor --json` | backend verdicts (no `schema`) | `crates/pod-netns` doctor tests |
| [ ] | `bug-report [--doctor]` | text with the doctor JSON | `bug_report.rs` tests |

## 9. Examples of the manual (`manual::facts::EXAMPLES`)

Pinned by `src/main.rs::each_example_of_the_manual_parses` (each parses with the clap tree).

- [ ] `cfrs doctor`
- [ ] `cfrs agent up`
- [ ] `cfrs tunnel --url http://127.0.0.1:8080 --detach`
- [ ] `cfrs ps --json`
- [ ] `cfrs relay pair`
- [ ] `cfrs relay node --to 127.0.0.1:22`
- [ ] `cfrs update --check`
- [ ] `cfrs demo --exit-on-verify`
- [ ] `cfrs tunnel --url http://127.0.0.1:8080`
- [ ] `cfrs tunnel --unix /run/app.sock`
- [ ] `cfrs tunnel --protocol http2 --url http://127.0.0.1:8080`
- [ ] `cfrs tunnel --transport warp --hello-world`
- [ ] `cfrs tunnel --token TOKEN --url http://127.0.0.1:8080`
- [ ] `cfrs tunnel --config config.yml`
- [ ] `cfrs tunnel --forward unix:/run/app.sock`
- [ ] `cfrs connect wss://NAME.trycloudflare.com/__cfrs/ws -L tcp://127.0.0.1:8080`
- [ ] `cfrs serve --dir ./public`
- [ ] `cfrs serve --dir ./public --local 127.0.0.1:8080`
- [ ] `cfrs serve --dir ./public --local unix:/run/site.sock`
- [ ] `cfrs share --mode upload --password`
- [ ] `cfrs share --mode proxy --unix /run/api.sock`
- [ ] `cfrs warp status`
- [ ] `cfrs warp proxy --listen tcp://127.0.0.1:40000`
- [ ] `cfrs warp run -- curl https://www.cloudflare.com/cdn-cgi/trace`
- [ ] `cfrs pod -x socks5://127.0.0.1:1080 -- curl https://example.com`
- [ ] `cfrs net proxy --forward 10.66.0.2:8080=unix:/run/app.sock`
- [ ] `cfrs net switch --listen tcp://127.0.0.1:7000 --switch-token-file /run/secrets/switch`
- [ ] `cfrs status`
- [ ] `cfrs man --roff`

## 10. Library surface (crate `cfrs`, `src/lib.rs`)

The library is public (docs.rs metadata, README section "Library"). The
rustdoc index of 2026-11-04 lists 1127 public items (554 fn, 247 const,
223 struct, 77 enum, 15 type, 9 trait, 2 static) in 52 modules. Keep each
path under the new crate name with `pub use` re-exports in the facade
(`podnet::warp::WarpClient`, `podnet::tunnel::Tunnel`, ...). The rename
itself changes `cfrs::` to `podnet::` (a breaking change: record it in the
release note `## Breaking`).

- [ ] root re-exports: `Config`, `Credentials`, `Protocol`, `ReconnectPolicy`, `Transport` (config); `Proxy` (egress); `ForwardTarget`, `Ingress`, `IngressRule`, `OriginOptions`, `Service` (ingress); `Metrics`, `MetricsSnapshot`; `ShareApp`, `ShareConfig`, `ShareControl`, `ShareMode`; `Tunnel`, `TunnelBuilder`, `TunnelHandle`, `Verified`; `NetStack`, `VirtAddr`, `VirtualSubnet` (vnet); `Identity`, `MasqueSession`, `StackConfig`, `WarpClient`, `WarpStack` (warp); `LocalSpec` (ws); fn `init_crypto`
- [ ] public modules (item count): warp 266, vnet 191, cloudflare 86, detach 29, manual 29, update 28, edge_h2 25, instances 25, autostart 23, origin 19, relay_reverse 19, relay_pool 19, egress 18, feature 18, util 18, state 18, doctor 16, exit 15, quicktunnel 15, report 15, resolve 15, transport 14, agent 13, config 13, trust 13, proxy_auth 11, gate 10, tunnel 10, ws_relay 10, ws 10, udp 9, net 9, relay 8, tls_fragment 8, proxy 8, hop 7, share 7, connect 6, rlimit 6, edge_discovery 6, ingress 5, preflight 5, race 4, decisions 4, ports 4, qr 4, fetch 3, bug_report 3, status 3, metrics 2, service 2, yaml 2
- [ ] `#[doc(hidden)] pub mod fuzzing` (16 entry points for `fuzz/`)
- [ ] `vnet` re-exports `pod_netns::{socks, tailscale, upstream}`, `Dialer`, `TailscaleProxy`, `UpstreamProxy`, `ProxyKind`, `Rule`, `Upstream`
- [ ] `proxy` re-exports `connect::{base64_encode, base64_encode_pub, connect_tunnel, connect_tunnel_with_auth, strip_scheme, TunnelStream}` (old paths)
- [ ] library-only subsystem (no caller in the binary): `feature` (AccessController, IpFilter, HttpBasicAuth, QR, StaticServer, StaticResponse, ShareLink), `origin` (Origin, StaticDir, tcp, unix_socket), `transport` (Transport trait: direct, HTTP CONNECT, SSH, WebSocket), `relay` (SSH port-forward relay), `util::http`, `util::tls`. Pinned only by their unit tests (feature 38, origin 25, transport 20, relay 8, util 17) and README lines 475-477
- [ ] crate `pod_netns` public API: `dns`, `listen`, `raw`, `socks`, `tailscale`, `upstream`, `ProxyListen`, `Net`, `Proxy`, `ProxyKind`, `Rule`, `RuleMatch`, `Upstream`, `set_program_name`, `usage`, `usage_for`, `main_with_args`, `QUIET_VARIABLE`

Pinned by: `tests/api_surface.rs` (the README shapes compile: quick tunnel,
transports, WarpClient, Identity, MasqueSession), `cargo doc -D warnings`
(ci.yml), `cargo package --list` for `cfrs` and `pod-netns` (ci.yml).
Recommended new pin: a public-API snapshot (the item list of
`target/doc/<crate>/all.html`, sorted, in a test fixture) taken before the
first move and compared after each move.

## 11. Unit tests by module (src/, 751 tests; crates/pod-netns/src, 43)

These tests move with their module. A move that loses a test is a
regression: compare `cargo test --workspace -- --list | wc -l` before and
after each move commit (1004 tests at 3bed023: 751 + 43 + 210).

| Module | Tests | Module | Tests |
| --- | --- | --- | --- |
| warp/ | 140 | vnet/ | 84 |
| cloudflare/ | 66 | feature/ | 38 |
| main.rs | 26 | origin/ | 25 |
| share | 20 | quicktunnel | 20 |
| transport/ | 20 | proxy | 19 |
| edge_h2 | 18 | egress | 17 |
| util/ | 17 | update | 15 |
| config | 15 | state | 12 |
| gate | 11 | tunnel | 10 |
| resolve | 9 | relay_reverse, relay, proxy_auth, instances | 8 each |
| manual/, ws_relay, trust, report, fetch, autostart, agent | 7 each | ws, race, preflight, doctor, detach, connect | 6 each |
| yaml, relay_pool, ingress | 5 each | udp, tls_fragment, net, exit, edge_discovery | 4 each |
| qr, hop | 3 each | rlimit, ports, bug_report | 2 each |
| status, service, metrics, fuzzing, decisions | 1 each | pod-netns src | 43 |

Integration tests (210): `tests/cli.rs` 55, `crates/pod-netns/tests/seccomp.rs` 30,
`tests/install_script.rs` 23, `tests/detach.rs` 20, `tests/docs.rs` 11,
`tests/shim_direct.rs` 11, `tests/relay_reverse.rs` 10, `tests/egress.rs` 8,
`tests/vnet_regressions.rs` 8, `tests/shim_no_socket.rs` 6, `tests/connect.rs` 5,
`tests/af_inet_kernel.rs` 4, `tests/doctor.rs` 3, `tests/signals.rs` 3,
`tests/tls.rs` 3, `crates/pod-netns/tests/usage.rs` 3, `tests/api_surface.rs` 2,
`tests/shim_socks.rs` 1, `tests/tcp_window.rs` 1, `tests/update_umask.rs` 1,
`tests/vnet_proxy_forward.rs` 1, `crates/pod-netns/tests/raw.rs` 1.

## 12. live.yml steps (`.github/workflows/live.yml`, 969 lines)

Each step must exist in the podnet live workflow with the new binary name,
or be replaced by a step that checks the same thing.

- [ ] L48 A planted failure (`inputs.plant == 'fail'`)
- [ ] L58 No step drops the masks (`live-run.sh` output not sent to /dev/null)
- [ ] L65 Toolchain; L70 Build (`cargo build --locked --release --bin cfrs`)
- [ ] L74 Edge facts (`tools/edge-facts.sh`)
- [ ] L78 `doctor`, `doctor --json`: legs quic, http2, quic+warp ok; roads direct, warp, relay ok; clock ok; api DNS addresses
- [ ] L94 `demo --exit-on-verify --protocol quic --transport direct`
- [ ] L97 `demo --exit-on-verify --protocol http2 --transport direct`
- [ ] L100 `demo --exit-on-verify --json`: ready url and leg, verified url and dns
- [ ] L113 `tunnel --hello-world --run-for 60 --json`, SIGTERM after the ready line: exit 0, `SIGTERM: stopping`
- [ ] L132 `tunnel --hello-world --detach --name live`, `ps --json` ready, `logs live -n 5`, `stop live`, `ps --json` empty
- [ ] L152 `tunnel --hello-world --auth-user live --auth-password-file F --detach --name auth`: curl with the password
- [ ] L171 UDP 7844 dropped: `demo --exit-on-verify` wins with `leg=http2`
- [ ] L179 Remove the UDP rule
- [ ] L185 `net doctor` UDP answered, then refused; `demo` names the refused probe, `leg=http2`
- [ ] L199 local CONNECT proxy (`scripts/connect-proxy.py`): `HTTPS_PROXY=... demo`; `--proxy 'http+exec:nc 127.0.0.1 18080' demo`; the CONNECT log has the API, 7844 and the URL
- [ ] L219 throughput of the HTTP path and of a `--forward` WebSocket (`scripts/live-throughput.sh` quic, http2)
- [ ] L228 large share uploads (`scripts/live-share.sh` quic, http2, 20 and 64 MB)
- [ ] L235 WebSocket through a `--url` origin (`scripts/live-ws-url.sh` quic, http2)
- [ ] L243 throughput through WARP, 1 to 16 MiB (`live-throughput.sh ... warp`)
- [ ] L248 no system DNS: `demo --protocol http2` uses DoH (`step="doh"`); 1.1.1.1 blocked: the 8.8.x.x DoH server
- [ ] L283 `--resolve api.trycloudflare.com=8.8.8.8 demo` fails at the TLS name check
- [ ] L294 `update --check`; `update --version v0.3.0-beta.1` (version and commit checked); `update --rollback`
- [ ] L317 `autostart add live -- tunnel --hello-world --json` (systemd user unit, ready line in the journal, URL answers); `autostart add secret -- status --proxy=...` (no secret in the unit or in ps; env file 0600); `autostart remove`
- [ ] L356 `demo --protocol quic --transport warp`
- [ ] L361 UDP and TCP 7844 dropped: `doctor --samples 3 --json` (only quic+warp ok); `demo` wins with `leg=quic+warp`
- [ ] L381 7844 dropped: `demo --check --transport relay` names `http2+relay`; `demo --transport relay` registers over HTTP/2; no relay token in the output
- [ ] L398 `relay pair --json`; `relay node NAME --to 127.0.0.1:22 --detach --name relaynode`; ssh with `ProxyCommand=cfrs relay connect NAME` (one and two parallel sessions); banner; `ps --json` `.ready.pair`; `relay stop NAME`; the node instance ends
- [ ] L446 `warp register`, `warp status`, `warp probe` (udp 1.1.1.1:53 OK), `warp nc -u 1.1.1.1 53`
- [ ] L463 WARP API through `api.devices.cloudflare.com`: `warp --identity F register`, `status`, `delete`
- [ ] L487 exit 69: `warp tun`, `warp proxy --listen`, `warp up --tun` (names `warp tun --default-route --detach` and the root hint)
- [ ] L510 MASQUE TCP dropped: `warp probe` through the WebSocket relay
- [ ] L525 `warp up --port 40097` with its TCP listener refused (`.tcp == false`); `warp env` names `warp exec`; `warp exec -- curl` (`warp=on`); `warp down`
- [ ] L549 `warp up --port 40100 --persist` (`.name == "warp"`, `.persist`, marker blocks); `eval "$(warp env)"`; `warp exec` with no proxy variables; git over `warp nc %h %p`; `warp nc -u`; `doctor --agent --json` (`warp_up`, rows git SSH and HTTPS); `warp ssh-config --host/--write/--check/--remove/--config`; second `warp up` keeps the pid; `SSL_CERT_FILE` with one root; `warp down` removes the blocks; `warp env` fails after down
- [ ] L623 `agent up --expose 18096 --expose 18097`: exposed[0] ready, exposed[1] origin-unreachable, mode warp, works git (SSH) via warp; `agent down`; `ps --json` empty
- [ ] L656 `warp run --backend netns-raw -- sh raw-check.sh` (TCP, UDP, IPv6, no root)
- [ ] L684 `sudo warp --ephemeral tun --default-route --detach --name tun` (`.default_route`), then everything as before after `stop tun` (log line)
- [ ] L711 `warp --ephemeral --no-relay tun --default-route --detach` in a netns with no default route and a CONNECT proxy only
- [ ] L753 `warp run --backend seccomp -- curl` and a UDP program
- [ ] L772 `warp proxy --listen tcp://127.0.0.1:40000 --dns 127.0.0.1:15353 --run-for 150`: SOCKS5 UDP DNS (IPv6, IPv4, a name: ATYP 3), curl through socks5h (`warp=on`, IPv6-only host, IPv6 literal), TCP burst against beta.6
- [ ] L900 `scripts/live-batch2.sh`: `warp exit --json`; `warp scan --candidate 162.159.198.1 --json`; `warp proxy` with rules; `warp forward -L 127.0.0.1:18443=1.1.1.1:443`; nested session (`--proxy socks5h://127.0.0.1:40010 warp ... proxy`); `warp export --format json`, `--delete`; `--fragment-client-hello` probe; `--cc` proxy upload; `--masque-transport h3` probe and proxy; `CFRS_WARP_TCP_BURST`; `warp proxy --l4 --l4-sni` with `CFRS_WARP_L4_FORM`; `--transport wireguard` probe and proxy; `--carry wg exit --json`
- [ ] L907 an IPv6-only host (`scripts/v6only/up.sh`, `acceptance.sh`, `down.sh`)
- [ ] L915 the test box (`scripts/test_in_box.sh`); L918 the test box fails with a binary that exits 3 (`BOX_PLANT=exit3`)
- [ ] L924 remove the WARP device (`warp delete`)
- [ ] job `report` L948: open one issue after two failed runs

## 13. Other gates

- [ ] `ci.yml`: fmt; clippy `--workspace --all-targets -D warnings`; `cargo test --workspace`; `cargo doc -D warnings`; `cargo package --list -p cfrs -p pod-netns`; man page (`cfrs man --roff`); MSRV 1.89 check (`-p cfrs --lib`); static musl builds; `restricted-host` (`scripts/restricted-host.sh`, bind of AF_INET refused); `Cargo.lock` current; `scripts/check-workflows.py`
- [ ] `release.yml`: cargo-zigbuild targets, armv7 in Alpine, binaries `cfrs` and `pod-netns` per target, SHA256SUMS, cosign bundle, `cargo about` notes; `release-proofs.yml`
- [ ] `cfrs update`: asset names `cfrs-<target>`, cosign identity `release.yml` at the tag, `CFRS_REPO`; a rename must keep an update path from the last cfrs release to the first podnet release
- [ ] `fuzz/` targets (16): acl_rule, capnp_message, capsule, config_yaml, connect_request, connect_response_head, doh_json, h2_header_block, ingress_rule, no_proxy, proxy_url, register_response, request_head, rpc_message, srv_record, vnet_frame; `seed` bin; `fuzz.yml` weekly
- [ ] `deny.yml`, `secrets.yml` (`.github/secrets-allow.txt`), `upstream.yml` (cloudflared changes, `src/cloudflare/cloudflared-pin.txt`)
- [ ] `tests/docs.rs`: each path in backticks in the documents exists; release notes have `## Breaking`; README rules; `crates/pod-netns/LICENSE` equals `LICENSE`; README notebook cell
- [ ] `scripts/install.sh` (`tests/install_script.rs`, 23 tests)

## 14. Commands with no behaviour test

Only the always-on pins of section 3 cover these. Add a test before the
move, or accept the risk in writing: `bug-report`, `qr`, `net demo`,
`warp license`, `warp rotate`, `warp shell`, `autostart run`,
`agent status`, `serve` (only usage and `--local` tests), `wait` (no live
step). `warp register`, `warp status`, `warp exit`, `warp export`,
`warp forward`, `warp tun`, `warp run`, `warp proxy` and `relay pair`
have live steps only (no loopback test of the command): a refactor of
these is proven only by a run of `live.yml`. `relay node` and
`relay connect` have library tests (`tests/relay_reverse.rs` calls
`cfrs::relay_reverse::{node, run_node, connect}` against a fake relay),
not command tests.
