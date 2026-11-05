# podnet: target architecture, file splits, parity inventory

Study of `/workspace/cfrs` at `3bed023` (2026-11-04, `v0.3.0-beta.12` + 3
commits). Read only. Data and scripts of this study:
`study/data/` (`man.json` = `cfrs man --json` of `target/debug/cfrs`
built after the last CLI change; `graph.json` = module graph;
`testmap.json` = tests per command; `filelist.md`) and `study/tools/`
(`graph.py`, `edges.py`, `outline.py`, `outline2.py`, `testmap.py`,
`live_steps.py`, `gen_checklist.py`). The checklist is
`study/parity-checklist.md`.

## 0. Summary

* 163 `.rs` files, 90 814 lines: `src/` 71 612 (106 files), `crates/pod-netns`
  10 554 (19), `tests/` 8 586 (21), `fuzz/` 62 (17). 32 files are over 800
  lines; 29 more are between 501 and 800 (they matter if podnet adopts the
  500-line rule of podssh, `AGENTS.md` rule 5, checked by
  `scripts/check-repo.py`).
* `src/main.rs` has 7 103 lines (6 455 code, 649 tests). Its `warp()`
  function alone has 1 089 lines; `WarpArgs` + `WarpCommand` have 543.
* 9 of the 32 large files are large only because of their `mod tests`.
  Moving the tests to `foo/tests.rs` brings them under 800. 19 source
  files need a real split (`src/main.rs` and 18 library files), and 4 are
  test files (section 2).
* The library modules form one strongly connected component of 26
  modules and 47 671 lines (each module of the component reaches each
  other through `crate::` references). A crate split is not possible
  before 18 small edges are cut (section 3.3). Each edge uses 1 to 4
  items (a constant, a helper, an error type, a small wrapper). After
  the cuts, the simulation in section 3.4 gives no upward edge between
  the proposed crates, and only two small cycles that stay inside one
  crate.
* Recommendation: (A) add a size check and a layer check, (B) split the
  files inside the current crate, (C) cut the 18 edges inside the crate,
  (D) rename, (E) extract 7 library crates bottom-up plus the root
  `podnet` package (CLI + facade), (F) add the network and service traits.
  Each step is a series of green commits (section 4.6).
* Parity: 63 commands, 8 global options, 316 own flags and arguments, the
  `pod-netns` CLI (11 options), 58 entries of environment variables (about
  90 names), 17 file entries, 8 exit codes, 30 JSON documents, 29 manual
  examples, 1 127 public library items, 46 live.yml steps, 1 004 tests.
  `study/parity-checklist.md` lists each one, with the tests that pin it.

## 1. Measure

### 1.1 Files over 800 lines (32)

| File | Lines | Code | Tests in file | Action |
| --- | --- | --- | --- | --- |
| `src/main.rs` | 7103 | 6455 | 649 | split into `src/cli/` (2.1) |
| `tests/cli.rs` | 2305 | - | 55 tests | `tests/cli/main.rs` + modules (2.4) |
| `src/feature/mod.rs` | 2139 | 1375 | 765 | split (2.2) |
| `src/vnet/stack.rs` | 2103 | 1882 | 222 | split (2.2) |
| `src/proxy.rs` | 2034 | 1242 | 793 | split (2.2) |
| `crates/pod-netns/tests/seccomp.rs` | 2018 | - | 30 tests | `tests/seccomp/main.rs` + modules (2.4) |
| `src/warp/proxy.rs` | 1991 | 1375 | 617 | split (2.2) |
| `src/share.rs` | 1901 | 1146 | 756 | split (2.2) |
| `crates/pod-netns/src/seccomp.rs` | 1900 | 1900 | 0 | split (2.2) |
| `src/edge_h2.rs` | 1736 | 1138 | 599 | split (2.2) |
| `src/egress.rs` | 1707 | 1352 | 356 | split (2.2) |
| `src/warp/ip.rs` | 1680 | 1265 | 416 | split (2.2) |
| `src/tunnel.rs` | 1599 | 1348 | 252 | split (2.2) |
| `src/doctor.rs` | 1309 | 1130 | 180 | split (2.2) |
| `src/warp/session.rs` | 1211 | 816 | 396 | tests out + 1 module (2.2) |
| `src/detach.rs` | 1210 | 1108 | 103 | split (2.2) |
| `src/config.rs` | 1204 | 755 | 450 | tests out (2.3) |
| `crates/pod-netns/src/netns.rs` | 1199 | 1199 | 0 | split (2.2) |
| `src/update.rs` | 1162 | 802 | 361 | tests out + 2 modules (2.2) |
| `src/relay_reverse.rs` | 1139 | 924 | 216 | split (2.2) |
| `src/cloudflare/http2.rs` | 1123 | 520 | 604 | tests out (2.3) |
| `src/warp/mod.rs` | 1105 | 972 | 134 (`private_file_tests`) | split (2.2) |
| `src/warp/wg.rs` | 1078 | 812 | 267 | split (2.2) |
| `src/vnet/switch.rs` | 1072 | 710 | 363 | tests out (2.3) |
| `src/warp/up.rs` | 1043 | 745 | 299 | tests out (2.3) |
| `crates/pod-netns/src/upstream.rs` | 1040 | 772 | 269 | tests out (2.3) |
| `src/ws_relay.rs` | 995 | 757 | 239 | tests out; also split for layering (3.3) |
| `src/cloudflare/capnp.rs` | 944 | 724 | 221 | tests out (2.3) |
| `src/warp/register.rs` | 936 | 726 | 211 | tests out (2.3) |
| `src/quicktunnel.rs` | 892 | 520 | 373 | tests out (2.3) |
| `tests/shim_direct.rs` | 822 | - | 11 tests | harness to `tests/shim_harness/mod.rs` (2.4) |
| `tests/detach.rs` | 812 | - | 20 tests | `tests/detach/main.rs` + modules (2.4) |

Files of 501 to 800 lines (29; only for a 500 rule): `src/autostart.rs` 791,
`src/warp/route.rs` 790, `crates/pod-netns/src/socks.rs` 746, `src/agent.rs`
692, `src/cloudflare/rpc.rs` 691, `src/vnet/doctor.rs` 672,
`tests/install_script.rs` 670, `src/vnet/control.rs` 670, `src/relay.rs` 668,
`src/preflight.rs` 656, `src/vnet/device.rs` 639, `src/instances.rs` 636,
`src/warp/h3.rs` 622, `src/proxy_auth.rs` 615, `src/report.rs` 612,
`src/manual/facts.rs` 610, `src/origin/static_files.rs` 608, `src/ws.rs` 596,
`src/resolve.rs` 591, `src/state.rs` 583, `src/vnet/addr.rs` 581,
`src/ingress.rs` 580, `tests/relay_reverse.rs` 568,
`crates/pod-netns/src/tailscale.rs` 556, `src/fetch.rs` 548, `src/yaml.rs` 530,
`src/vnet/proxy.rs` 514, `src/transport/websocket.rs` 510,
`crates/pod-netns/src/inbox.rs` 503.

The full list of the 163 files with their line counts is Appendix A.

## 2. Split proposals

Rules for each split:

* Move code verbatim (cut and paste, `git mv` for the first part). Change
  only `use` lines and visibility (`pub(super)` or `pub(crate)` for an
  item that a sibling module now needs).
* Keep each public path with `pub use` in the parent `mod.rs`
  (`crate::egress::Proxy`, `cfrs::vnet::NetStack`, ...). The library is
  public (README "Library", docs.rs metadata, `tests/api_surface.rs`).
* Use the `mod.rs` form (the repository uses it: `src/warp/mod.rs`).
* A test module moves to `foo/tests.rs` as `#[cfg(test)] mod tests;`. As a
  child module it keeps `use super::*;` and its access to private items.
* Do not name a child module as its parent (`warp/proxy/proxy.rs`):
  clippy `module_inception` fails with `-D warnings`.
* Each commit: `sh scripts/agent/check.sh`, the same test count
  (`cargo test --workspace -- --list 2>/dev/null | grep -c ': test$'`),
  and the paths in the documents updated in the same commit
  (`tests/docs.rs::each_path_in_the_documents_exists` fails otherwise).

### 2.1 `src/main.rs` (binary only: no public path)

The binary declares `mod cli;`; the library does not declare it, so
`src/cli/` belongs to the binary only. Line ranges are of `src/main.rs`
at 3bed023.

| New file | Lines (approx.) | Moves from `src/main.rs` |
| --- | --- | --- |
| `src/main.rs` | 300 | macros `println!`/`print!`/`eprintln!` (1-26), `use` lines, `main()` (847-1081) |
| `src/cli/mod.rs` | 400 | `Cli` (53-103), `Command` (104-228), `async_main` dispatch (2476-2682) |
| `src/cli/argv.rs` | 300 | `LOG_JSON`, `CLOUDFLARED_FLAGS`, `cloudflared_compat`, `read_token_file`, `apply_token_files`, `no_terminal`, `SERVER_COMMANDS`, `foreground_hint` (1082-1294); `command_name`, `pod_network_option`, `pod_args_of` (2406-2475) |
| `src/cli/help.rs` | 240 | `HELP_GROUPS`, `START_HERE`, `first_sentence`, `grouped_commands`, `top_command`, `example_path`, `with_examples`, `usage_hints`, `word_hint`, `json_wanted`, `error_json`, `print_error` (1295-1531) |
| `src/cli/signals.rs` | 130 | `STOP`, `signal_ignored`, `install_signals`, `shutdown_signal`, `sleep_or_signal`, `deadline_of`, `sleep_until_opt`, `until_stop_or` (1532-1659) |
| `src/cli/opts.rs` | 280 | `TunnelOpts` + impl, `Show`, `DetachArgs` + impl (371-576); `detach_of`, `network_options` (2341-2405) |
| `src/cli/cmd/tunnel.rs` | 250 | `TunnelArgs` (577-628), `tunnel`, `preflight`, `split_host_port`, `pick_optional_service` (2683-2807, 2917-2986) |
| `src/cli/cmd/run.rs` | 340 | `run_tunnel`, `run_share`, `run_demo`, `serve_until`, `tunnel_doc`, `listen_doc` (3448-3648); `verified`, `announce`, `announce_text`, `wait`, `idle_watch`, `wait_with_idle`, `wait_controls`, `_mode` (3851-3985) |
| `src/cli/cmd/share.rs` | 400 | `ServeArgs`, `ModeArg`, `ShareArgs`, `DemoArgs` (629-721, 826-846); `serve`, `serve_local`, `share_mode`, `share`, `demo`, `default_upload_dir` (3187-3447) |
| `src/cli/cmd/connect.rs` | 240 | `ConnectArgs` (779-819); `connect`, `accept_loop`, `SocketFile`, `file_id`, `unix_listener`, `accept_unix` (2987-3186) |
| `src/cli/cmd/relay.rs` | 230 | `RelayArgs`, `RelayCommand` (722-778); `relay`, `RelayIo`, `non_empty_key` (3649-3824) |
| `src/cli/cmd/agent.rs` | 280 | `AgentCommand` (272-296); `run_self_json`, `agent`, `license_fault`, `exposes_failed` (1660-1854); `agent_commands` (2229-2245) |
| `src/cli/cmd/instances.rs` | 180 | `instances_ps`, `instances_stop`, `instances_logs` (1855-2032) |
| `src/cli/cmd/autostart.rs` | 130 | `AutostartArgs`, `AutostartCommand` (229-271); `autostart_args`, `autostart` (2808-2891) |
| `src/cli/cmd/host.rs` | 150 | `DoctorArgs`, `ManArgs`, `UpdateArgs`, `parse_release_tag`, `PortsArgs`, `QrArgs` (297-370, 820-825); the arms of `status`, `doctor`, `man`, `update`, `ports`, `qr`, `bug-report`, `completions` from `async_main` |
| `src/cli/cmd/warp/mod.rs` | 160 | `warp()` prologue (4669-4707) and the dispatch to the files below |
| `src/cli/cmd/warp/args.rs` | 545 | `WarpArgs` (3993-4155), `WarpCommand` (4156-4535) |
| `src/cli/cmd/warp/client.rs` | 135 | `warp_client`, `carry_peer`, `wireguard_peer`, `masque_options`, `identity_pairs`, `warp_client_inner` (4536-4668) |
| `src/cli/cmd/warp/up.rs` | 460 | arms `Up`, `Down`, `Env`, `Exec`, `Shell`, `SshConfig`, `Nc` (4708-4818, 5640-5675); `UpFiles`, `warp_up`, `up_summary`, `UDP_NC_IDLE`, `nc_end`, `udp_nc`, `ssh_config_file`, `warp_global_args`, `warp_up_tun_args`, `warp_up_args` (2033-2340 without `agent_commands`) |
| `src/cli/cmd/warp/account.rs` | 200 | arms `Register`, `Status`, `License`, `Rotate`, `Delete` (4927-5047); `print_device` (5817-5843); `plain_value`, `warp_plus_label` (3825-3850) |
| `src/cli/cmd/warp/probe.rs` | 200 | arms `Scan`, `Exit`, `Probe` (5048-5224); `parse_door`, `exit_line` (2892-2916) |
| `src/cli/cmd/warp/export.rs` | 80 | arm `Export` (4819-4891) |
| `src/cli/cmd/warp/front.rs` | 290 | arms `Proxy` (4892-4926, 5225-5396) and `Forward` (5397-5473) |
| `src/cli/cmd/warp/tun.rs` | 170 | arm `Tun` (5474-5639) |
| `src/cli/cmd/warp/run.rs` | 145 | arm `Run` (5676-5757), `warp_run_raw` (5758-5816) |
| `src/cli/cmd/net/mod.rs` | 310 | `NetArgs` (3986-3992), `NetCommand` and its args structs (5844-6024), `net()` (6025-6144) |
| `src/cli/cmd/net/proxy.rs` | 160 | `probability`, `net_proxy`, `RealTarget`, `DialStream` (6178-6342) |
| `src/cli/cmd/net/shim.rs` | 160 | `net_shim`, `net_tailscale`, `print_environment`, `net_socksify`, `net_ts_shims` (6145-6177, 6343-6454) |
| tests (649) | | to the module of each function: `cli/help/tests.rs` (help lint, groups, examples, word hint, unknown command, ~220), `cli/argv` tests (cloudflared, command name, pod double dash, bad command line, ~120), `cmd/share` (~70), `cmd/warp` (identity pairs, front doors, warp up tun, summary, probe targets, warp proxy of warp up, license/status fields, ~170), `cmd/agent` (~50), `cli/manual_tests.rs` (`the_command_tree_is_valid`, `each_example_of_the_manual_parses`, `the_manual_names_each_command_and_flag`, ~60) |

The largest new file is `cmd/warp/args.rs` (545). It is under 800; for a
500 rule, move the subcommand structs of `WarpCommand::Proxy` (93 lines)
and `Up` (56) to `args/front.rs`. Order of the commits: signals, help and
argv, opts, instances/autostart/agent/host, tunnel/run/share/connect/relay,
warp (2 commits), net, tests.

### 2.2 Library files that need a real split (public paths kept)

| File (code lines) | New modules (approx. lines) |
| --- | --- |
| `src/vnet/stack.rs` (1882) | `stack/mod.rs`: `NetStack`, `StackConfig`, `StackEvent`, `Clock`, re-exports (400); `stack/socket.rs`: `TcpStream`, `UdpSocket`, their `AsyncRead`/`AsyncWrite`/`Drop`, `SocketCount` (420); `stack/core.rs`: `Core::new`, `listen`, `connect`, `bind_udp` (330); `stack/service.rs`: `Core::service_dns`, `accept_inbound`, `service_conns` (181), `service_udp` (350); `stack/run.rs`: `run` loop and timers (120); `stack/proof.rs`: `ProofReport`, `loopback_proof`, `loopback_round_trip` (250); `stack/tests.rs` (222) |
| `src/proxy.rs` (1242) | `proxy/mod.rs`: `serve_stream`, `serve_request_inner`, `serve_decoded`, the `connect::*` re-exports (330); `proxy/forward.rs`: `forward_http`, `proxy_bidi`, `forward_tcp` (170); `proxy/axum.rs`: `dispatch_axum`, `pump_body`, `write_axum_response` (160); `proxy/share.rs`: `share_proxy`, `percent_decode` (150); `proxy/head.rs`: `build_request_head`, `response_length`, `read_response_head`, `header_value`, `write_response_meta`, `MAX_HEADERS` (250); `proxy/chunked.rs`: `copy_chunked_to_futures`, `futures_close` (120); tests (793) to `proxy/tests/{mod,upload,head,forward}.rs` |
| `src/warp/proxy.rs` (1375) | `warp/proxy/mod.rs`: `bind`, `bind_all`, `admit`, `run`, `run_l4`, `WarpProxy`, `health_log` (300); `proxy/dns.rs`: `serve_dns`, `Resolver`, `exchange_any`, `exchange`, `dot_exchange`, `forward_dns_to`, `query`, `query_at`, `resolve_all`, `resolve`, `Names` (400); `proxy/socks.rs`: `handle_client_auth`, `client_on` (230); `proxy/udp.rs`: `UdpClient`, `udp_associate_on`, `udp_in_stream` (190); `proxy/route.rs`: `route`, `direct`, `dial_ips`, `order`, `check_data_path`, `check_data_path_at`, `bridge`, `Prefixed` (260); tests (617 + `order_tests`) to `proxy/tests.rs` |
| `src/share.rs` (1146) | `share/mod.rs`: `ShareMode`, `ShareConfig`, `ShareControl`, `ShareApp`, `content_disposition`, `no_store` (330); `share/upload.rs`: `upload_router`, `check_session`, `unlock_response`, `gate_blocked`, `upload_landing`, `Staging`, `next_chunk`, `drop_body`, `upload_receive` (195 lines alone), `upload_page`, `create_unique_with` (560); `share/download.rs`: `download_router`, `download_landing`, `download_file`, `parse_range` (260); tests (756) to `share/tests/{upload,download}.rs` |
| `crates/pod-netns/src/seccomp.rs` (1900, no tests) | `seccomp/mod.rs`: `run_seccomp`, `supervise_seccomp` (the notification loop, 187) (300); `seccomp/filter.rs`: `intercepted_syscalls`, `AUDIT_ARCH_NATIVE`, `install_notif_filter`, `resolve_program` (220); `seccomp/mem.rs`: `read_mem`, `write_mem_to`, `process_vm_writable`, `open_mem_of`, `warn_no_mem_write` (160); `seccomp/notif.rs`: `notif_addfd_send`, `notif_addfd_setfd`, `notif_respond`, `notif_continue`, `sockaddr_in`, `parse_sockaddr` (170); `seccomp/connect.rs`: `handle_socket`, `handle_connect`, `connect_loopback` (170); `seccomp/udp.rs`: `UdpRelay`, `Sock`, `spawn_relay`, `handle_sendto`, `handle_sendmmsg`, `handle_sendmsg`, `send_msghdr`, `ensure_udp_relay`, `relay_datagram` (480); `seccomp/listen.rs`: `handle_bind`, `handle_listen`, `drain_one`, `install_accepted`, `handle_accept` (210); `seccomp/sockopt.rs`: `handle_getsockopt`, `handle_sockname`, `handle_recv`, `wait_recv` (220). Note: `tests/docs.rs::the_seccomp_list_of_pod_netns_is_one_list` reads the README, not this file |
| `src/edge_h2.rs` (1138) | `edge_h2/mod.rs`: `connect`, `connect_one`, `register_served`, `dial`, `reactor` (330); `edge_h2/stream.rs`: `StreamType`, `stream_type`, `connect_request`, `edge_response`, `serve_stream`, `body_reader`, `pump_to_h2`, `answer_configuration`, `read_configuration` (330); `edge_h2/frames.rs`: `H2Leg`, `FrameScan`, `GoawayScan` (180); `edge_h2/serve.rs`: `serve_connection` (150); `Metered` (110) moves to the core (`metrics::Metered`, edge 9 of 3.3) with a `pub use`; tests (599) to `edge_h2/tests.rs` |
| `src/egress.rs` (1352) | `egress/mod.rs`: `ProxyChoice`, `set_choice`, `dial`, `dial_direct`, `dial_resolved`, `dial_addrs`, `proxy_for` (350); `egress/proxy.rs`: `Proxy`, `Proxy::parse`, `Proxy::connect`, `Display` (300); `egress/http_connect.rs`: `http_connect`, `reply_reason`, `explain_407`, `auth_schemes`, `parse_status`, `refusal` (260); `egress/socks5.rs`: `socks5_connect` (150); `egress/no_proxy.rs`: `NoProxy`, `parse_no_proxy_entry` (180); `egress/exec.rs`: `ChildIo` and the `+exec:` spawn, `split_host_port` (130); `pub use` keeps `egress::{Proxy, NoProxy, parse_status}` (used by `fuzzing`) |
| `src/warp/ip.rs` (1265) | `ip/mod.rs`: `StackConfig`, `WarpStack` and its impl (233), `TUNNEL_MTU` (450); `ip/conn.rs`: `TcpConn`, `UdpConn` (180); `ip/driver.rs`: `Command`, `Pending`, `Driver` (454) (550); `ip/iface.rs`: `build_iface`, `check_cc`, `check_tcp_burst` (110); tests (416) to `ip/tests.rs` |
| `src/tunnel.rs` (1348) | `tunnel/mod.rs`: `TunnelBuilder`, `Tunnel` public API, `TunnelHandle` + impl, `CLIENT_VERSION`, `EDGE_REGION_NAME`, `NO_INGRESS` (450); `tunnel/start.rs`: the body of `impl Tunnel` (334) (340); `tunnel/credentials.rs`: `resolve_credentials`, `split_explicit` (110); `tunnel/plan.rs`: `LegKind`, `leg_plan`, `plan_with_proxy`, `plan_with_udp`, `edge_override` (200); `tunnel/legs.rs`: `register_retrying`, `bounded`, `warp_targets`, `WarpLink`, `connect_once`, `reactor`, `Legs`, `spawn_leg` (340); `tunnel/verify.rs`: `verify_fetch`, `public_dns` (120); tests (252) |
| `src/doctor.rs` (1130) | `doctor/mod.rs`: `Options`, `run`, `Report` + `to_json` (207) (360); `doctor/targets.rs`: `Target`, `targets` (120); `doctor/path.rs`: `Path`, `path`, `stats`, `sample`, `classify`, `proxy_report` (300); `doctor/tls.rs`: `Recorder`, `Counting`, `verifier`, `tls` (260); `doctor/clock.rs`: `clock`, `clock_of`, `parse_imf_fixdate` (90); `doctor/legs.rs`: `names`, `legs` (110); tests (180) |
| `src/detach.rs` (1108) | `detach/mod.rs`: `prepare`, `is_child`, `update_record`, `child_begin`, `register`, `begin_log`, `same_file`, `ready`, `cap`, `retry_after`, `provision_budget` (450); `detach/start.rs`: `start`, `start_inner`, `strip`, `wait_ready_child`, `wait_ready_record`, `stop` (330); `detach/supervise.rs`: today's inline `mod supervise` (261); `detach/unix.rs`: today's inline `mod unix` (75); tests (103) |
| `crates/pod-netns/src/netns.rs` (1199, no tests) | `netns/mod.rs`: `run`, `child_setup`, `private_resolv_conf` (200); `netns/tun.rs`: `bringup_loopback`, `create_tun`, `Tun`, `impl Device for Tun` (250); `netns/fd.rs`: `send_fd_raw`, `send_fd`, `recv_fd`, `read_exact_fd`, `socketpair` (160); `netns/backend.rs`: `Backend` + impl (389), `tcp_socket` (440); `netns/packet.rs`: `dns_reply_packet`, `rst_reply_for_syn`, `parse_tcp_syn` (120) |
| `src/relay_reverse.rs` (924) | `relay_reverse/mod.rs`: `Pair`, `pair`, `save`, `load`, `stop`, `close_hint`, `EOF_IDLE` (320); `relay_reverse/node.rs`: `node`, `run_node`, `node_once`, `node_ready`, `Out`, `Gate`, `session` (420); `relay_reverse/connect.rs`: `connect` (190); tests (216) |
| `src/warp/mod.rs` (972 code) | `warp/mod.rs`: modules, re-exports, `WarpClient` + `register_with`, `load`, save, accessors (420); `warp/client_session.rs`: `connect_carried`, `connect_outer`, `open_session`, `open_on`, `scan` (330); `warp/private_file.rs`: `write_private`, `check_private` and `private_file_tests` (134) (200) |
| `src/feature/mod.rs` (1375) | `feature/mod.rs`: `FeatureError`, re-exports (80); `feature/access.rs`: `IpRange`, `IpFilter`, `IpVerdict`, `DenyReason`, `AccessDecision`, `HttpBasicAuth`, `AccessController`, `decode_base64` (580); `feature/qr.rs`: `QrStyle`, `render_qr`, `render_qr_with`, `qr_fits` (100); `feature/static_server.rs`: `BufferedResponse`, `StaticBody`, `StaticResponse`, `StaticServer` (450); `feature/share_link.rs`: `ShareLink` (170); tests (765) split by file |
| `src/warp/session.rs` (816) | `session/mod.rs` (600); `session/pin.rs`: `PinnedKey` (`ServerCertVerifier`), `Keepalive` (220); tests (396) to `session/tests.rs` |
| `src/update.rs` (802) | `update/mod.rs`: `Release`, `get`, `version_order`, `run`, `Outcome`, `FULCIO_PEM` (350); `update/cosign.rs`: `verify_bundle` and the certificate checks (250); `update/install.rs`: `trial`, `install_with`, `rollback_with`, `previous_of` (200); tests (361) |
| `src/warp/wg.rs` (812) | `wg/mod.rs`: `Peer`, `State`, `Sock`, `connect_on`, `WgTx`, `WgRx`, `WgKeepalive` (420); `wg/blake2s.rs`: `compress`, `blake2s`, HMAC/HKDF helpers (150); `wg/noise.rs`: `Keys`, `initiate_with`, `Initiation`, `Session`, `Replay` (250); tests (267) |

### 2.3 Files that need only their tests moved out

`src/config.rs` (755 code), `src/cloudflare/http2.rs` (520), `src/vnet/switch.rs`
(710), `src/warp/up.rs` (745), `crates/pod-netns/src/upstream.rs` (772),
`src/ws_relay.rs` (757; it is also split for the layers, 3.3),
`src/cloudflare/capnp.rs` (724), `src/warp/register.rs` (726),
`src/quicktunnel.rs` (520). Form: `foo.rs` becomes `foo/mod.rs` +
`foo/tests.rs`, or `foo.rs` + `foo/tests.rs` with `#[cfg(test)] mod tests;`.

### 2.4 Test files

* `tests/cli.rs` (2305, 55 tests) to `tests/cli/main.rs` (helpers `cfrs`,
  `stderr`, `trace`, `serve_local`, `http_get`, `stop`; `mod test_host;`) +
  `exit_codes.rs` (usage, 78, 64, flag values, invalid values, error shape),
  `log.rs` (log controls, json, colours, secrets, failure report),
  `manual.rs` (man page, listen defaults, completions), `detach_autostart.rs`
  (autostart, read commands, token file), `net.rs` (socksify, ts-shims,
  switch token, socket rule, port 0), `warp.rs` (status, ssh-config, env),
  `serve.rs` (check mode, share, serve --local). Cargo finds
  `tests/cli/main.rs` as the test target `cli`.
* `crates/pod-netns/tests/seccomp.rs` (2018, 30 tests) to
  `tests/seccomp/main.rs` (the SOCKS5 stand-in and helpers, ~300) +
  `tcp.rs`, `udp.rs`, `listen.rs`, `dns.rs`, `rules.rs`.
* `tests/shim_direct.rs` (822): the C compile and run harness to
  `tests/shim_harness/mod.rs` (shared with `shim_no_socket.rs` and
  `af_inet_kernel.rs`, which repeat parts of it).
* `tests/detach.rs` (812): `tests/detach/main.rs` + `supervise.rs`,
  `names.rs`, `logs.rs`.

## 3. Current module graph

### 3.1 Method

`study/tools/graph.py` reads each file of `src/`, cuts the `mod tests`
part, and counts each `crate::X` (and `cfrs::X` in `src/main.rs`). The
result is `study/data/graph.json`. `edges.py` lists the items of one edge.

### 3.2 Natural layers (sizes in lines, with tests)

| Layer | Modules | Lines |
| --- | --- | --- |
| Core: process and files | `exit` 203, `state` 583, `rlimit` 98, `report` 612, `hop` 210, `decisions` 96, `metrics` 135, `yaml` 530, `race` 257, `util/` 713, `qr` 119, `ports` 129 | 3 685 |
| Core: network | `net` 403 (part), `trust` 495, `egress` 1707, `proxy_auth` 615, `resolve` 591, `fetch` 548, `tls_fragment` 397, `udp` 246, `connect` 338 | 5 340 |
| Core: supervisor | `detach` 1210, `instances` 636, `autostart` 791 | 2 637 |
| Adapter: Cloudflare tunnel | `cloudflare/` 3956, `tunnel` 1599, `edge_h2` 1736, `edge_discovery` 314, `quicktunnel` 892, `config` 1204, `proxy` 2034 | 11 735 |
| Adapter: WARP | `warp/` (21 files) | 14 490 |
| Adapter: WebSocket relay | `ws_relay` 995, `relay_pool` 380, `relay_reverse` 1139 | 2 514 |
| Adapter: userspace networks | `vnet/` (14 files) | 8 394 |
| Adapter: pod backends | `crates/pod-netns` (netns, seccomp, raw, socks, tailscale) | 10 554 |
| Services | `share` 1901, `gate` 478, `service` 326, `ingress` 580, `ws` 596, `origin/` 1321, `feature/` 2139, `transport/` 1344, `relay` 668 | 9 353 |
| CLI and diagnostics | `main` 7103, `doctor` 1309, `preflight` 656, `agent` 692, `status` 202, `bug_report` 200, `manual/` 1627, `update` 1162, `fuzzing` 363, `lib` 150 | 13 464 |

Library-only subsystem: `feature`, `origin`, `transport`, `relay` (the SSH
port-forward relay) and `util::http`/`util::tls` (about 5 600 lines) have
no caller in the binary. Only their unit tests (108) and the README
(lines 475-477: `cfrs::origin::StaticDir`, `cfrs::feature::StaticServer`)
reach them. They are a capability of the library: keep them (the parity
rule), in the services crate.

`pod-netns` has no dependency on the root crate. The root crate uses it in
`src/main.rs` (16 references: `cfrs pod`, `warp run`), `src/vnet/` (8:
re-exports `socks`, `tailscale`, `upstream`), `src/warp/` (44: `warp run`
backends, rules, nc, forward) and `src/manual/model.rs` (the pod usage).
There are two proxy-URL parsers: `egress::Proxy::parse` (http, socks5,
socks5h, unix, +exec) and `pod_netns::upstream::Proxy::parse` (socks5,
http, unix, tailscale). Keep both for parity; a later network registry
can give one spec syntax with aliases.

### 3.3 The cycle, and the 18 edges to cut

26 modules are in one strongly connected component (47 671 lines):
`config detach edge_discovery edge_h2 egress feature fetch ingress net
origin proxy quicktunnel relay relay_reverse report resolve service share
tls_fragment tunnel update util vnet warp ws ws_relay`. The edges that go
from a lower layer to a higher one:

| # | Edge | Items | Fix (one small commit each) |
| --- | --- | --- | --- |
| 1 | `net` -> `ingress` | `{OriginOptions, Service}` | split `net.rs`: core keeps `BoxedIo`, `AsyncReadWrite`, `claim_socket_path`, `init_crypto`, `local_name`, `connect_origin` (lines 1-110); `dial`, `dial_unix`, `parse_http_url`, `tls_wrap`, connectors, `origin_label` (116-340) go to the services layer (`origin::dial`), with `pub use` in `net` |
| 2 | `util` -> `feature` | doc link to `StaticResponse` | change the doc link |
| 3 | `fetch` -> `proxy` | `MAX_HEADERS` | move the constant to `util::http`; `proxy` re-exports it |
| 4 | `hop` -> `cloudflare` | `rpc::Refused` (downcast) | tag at the error site (`.hop(Hop::EdgeRegister)` in `cloudflare::rpc`), or move a marker type `hop::Refused` to core |
| 5 | `report` -> `quicktunnel` | `retry_of` | move `Refusal` (status, code, retry_after_s) to core; `quicktunnel` attaches it as error context; `report` reads it by downcast |
| 6 | `detach` -> `update` | `previous_of` | move `previous_of` (the path of the kept binary) to core (`state` or `detach`) |
| 7 | `relay_reverse` -> `warp` | `register::utc_minutes` x2 | move the time helper to `util::time` |
| 8 | `ws_relay` -> `ws` | `bridge` | split `ws.rs`: `bridge`, `dial`, `connect_bridge`, `accept_key`, `LocalSpec`, `DIAL_TIMEOUT` go to core (`util::ws` or `ws_bridge`) |
| 9 | `ws_relay` -> `edge_h2` | `Metered::with_flag` | move `Metered` (edge_h2 lines 416-523) to `metrics` |
| 10 | `warp` -> `cloudflare` | `CF_EDGE_ROOTS_PEM`, `QUIC_ALPN`, `quic::transport_config` | `warp/quic.rs` keeps `WarpUdpSocket` and takes the client config as an argument; `client_config()` (edge roots, ALPN, MTU) moves to the tunnel side |
| 11 | `warp` -> `quicktunnel` | `parse_retry_after` | move to `util::http` |
| 12 | `feature` -> `quicktunnel` | `ShareLink::from_quick_tunnel` | give `ShareLink` a constructor from URL and id; the conversion from `QuickTunnel` moves to the Cloudflare side (or the facade) |
| 13 | `ingress` -> `config` | `RULE_KEYS` | move the constant to `ingress`; `config` re-exports it |
| 14 | `relay` -> `proxy` | `connect_tunnel` (re-export) | use `crate::connect` directly |
| 15 | `transport` -> `proxy` | `connect_tunnel`, `connect_tunnel_with_auth`, `base64_encode_pub` | use `crate::connect` directly |
| 16 | `ws` -> `cloudflare` | `stream` | `serve_websocket` and `forward_path` (edge stream side) move to the tunnel side, next to `proxy` |
| 17 | `ws` -> `proxy` | `header_value`, `write_response_meta`, `EdgeReader`, `EdgeWriter` | same move as 16 |
| 18 | `ws` -> `relay_reverse` | `close_hint` | move `close_hint` with the WebSocket close codes to the core `ws_bridge` |

### 3.4 After the cuts

`study/tools` simulation (the 18 edges removed, layers as in 4.1): no
upward edge. Two cycles remain, each inside one crate: `{egress, fetch,
report, resolve}` (core) and `{config, edge_h2, quicktunnel, tunnel}`
(Cloudflare). A layer check (`scripts/check-layers.py`, a table of module
to layer, fails on an upward `crate::` reference) can enforce this inside
one crate, before any crate exists.

## 4. Workspace layout for podnet

### 4.1 Crates

Dependency direction: each crate depends only on crates above it in this
table. `podnet-netns` depends on none.

| Crate | Path | Contents (today's modules) | Lines (approx.) |
| --- | --- | --- | --- |
| `podnet-netns` | `crates/podnet-netns` (from `crates/pod-netns`) | netns, seccomp, raw backends; socks, tailscale front door, upstream chains, dns, listen, inbox, fakedns, doctor, CLI parser; binary `pod-netns` (name: owner question) | 10 600 |
| `podnet-core` | `crates/podnet-core` | exit, hop, state, report, decisions, metrics (+ `Metered`), rlimit, yaml, race, util (+ `time`, `http` constants), qr, ports; net (io part), trust, egress, proxy_auth, resolve, fetch, tls_fragment, udp, connect, ws bridge; detach, instances, autostart; the `Dialer`/`Network` traits (4.3) | 11 700 |
| `podnet-vnet` | `crates/podnet-vnet` | vnet/ (stack, switch, shim builder, proxy, policy, record, tailscale_ssh); the C sources of `shim/` move into the crate (`include_str!` must stay inside the crate for `cargo package`) | 8 400 + C |
| `podnet-relay` | `crates/podnet-relay` | the relay client of `ws_relay` (`Relay`, `Host`, mint, token cache, `RelayBudget`, `websocket_at`), relay_pool, relay_reverse | 2 400 |
| `podnet-warp` | `crates/podnet-warp` | warp/ (register, MASQUE h2/h3, WireGuard, userspace stack, proxy, forward, tun, route, up, export, rules, nc, ssh_config) | 14 500 |
| `podnet-serve` | `crates/podnet-serve` | share, gate, service runtime, ingress rules (`Service` enum), origin (+ `origin::dial` from `net`), feature, transport, relay (SSH forward), ws forward client; the `Service`/`Ingress` traits (4.3) | 9 300 |
| `podnet-cloudflare` | `crates/podnet-cloudflare` | cloudflare/ (QUIC, HTTP/2, capnp RPC, schemas, edge roots), tunnel, edge_h2, edge_discovery, quicktunnel, config, proxy (edge stream dispatch), `ws::serve_websocket`, the HTTP/2 leg through the relay (from `ws_relay`), the QUIC client config of the quic+warp leg | 12 000 |
| `podnet` | root package (`.`) | binary `podnet` (`src/main.rs`, `src/cli/`), facade library (`pub use` of each old module path), doctor, preflight, agent, status, bug_report, manual, update, fuzzing | 13 500 |
| `podnet-testkit` | `crates/podnet-testkit` (`publish = false`) | `need_loopback!`, `need_localhost!` (today `tests/test_host/mod.rs`, included by `#[path]`); a dev-dependency of each crate | 100 |

Edges between crates after the cuts (from the simulation): vnet -> core,
netns; relay -> core; warp -> core, vnet (`device::LinkDevice`), relay
(MASQUE through the relay), netns (`warp run` backends); serve -> core;
cloudflare -> core, relay (http2+relay leg), warp (quic+warp leg), serve
(dispatch of edge streams to services); podnet -> all.

Keep the root package at the repository root: `tests/docs.rs` (11 tests,
`CARGO_MANIFEST_DIR` = the repository), `tests/cli.rs`,
`tests/install_script.rs`, the README as the crate readme and
`fuzz/Cargo.toml` (`path = ".."`) keep working.

### 4.2 One crate with modules, or many crates

| Point | One crate (+ pod-netns) | 8 crates |
| --- | --- | --- |
| Layering | by convention; enforced only by a script (`check-layers.py`) | enforced by the compiler; a cycle does not build |
| Debug build after an edit | the frontend (type and borrow check) of all 72 000 lines runs again; incremental codegen helps | only the crate of the edit and the crates that depend on it (an edit in `src/cli/` rebuilds ~13 500 lines) |
| Parallel build | one rustc frontend for the library | independent crates (vnet, relay, serve, netns) build in parallel |
| Release build | thin LTO, `codegen-units = 1`: no change expected in time or size | same (thin LTO inlines across crates) |
| Optional adapters | `#[cfg(feature)]` in one crate | a cargo feature of `podnet` per adapter crate; heavy later adapters (Tailscale with C, as `podssh-ts` with aws-lc and cmake) stay out of the default build (podssh `default-members`) |
| Fuzz crate | no change | `podnet::fuzzing` facade calls `#[doc(hidden)] pub mod fuzzing` of each crate (some targets use `pub(crate)` items: `proxy::build_request_head`); `fuzz/Cargo.lock` regenerated |
| `cargo package` | 2 packages | 8 packages; each `include_str!`/`include_bytes!` inside its crate: `shim/*.c`, `shim/tsgetent`, `shim/tsid`, `shim/fakepwd.c` (vnet), `cf-edge-roots.pem`, `cloudflared-pin.txt`, `schemas/` (cloudflare), `src/sigstore-fulcio.pem` (update, root); the test includes `../../tools/header-oracle.txt` (cloudflare http2 test) and `../Cargo.lock` (trust test) point outside a crate: move these two tests to the root package; a `LICENSE` copy in each crate (`tests/docs.rs::pod_netns_ships_the_license` generalised); ci.yml checks `shim/cfrsnet.c` in the package list of `cfrs` (move to `podnet-vnet`) |
| Docs tests | no change | no change if the root stays `podnet`; the paths in the documents change with each move (the test enforces it) |
| Environment scan | no change | `manual::facts` tests walk `src`, `crates/pod-netns/src`, `shim`: change to `src`, `crates/*/src`, the shim directory |
| Macros | in `src/lib.rs` | `println!`/`print!`/`eprintln!`/`update_atomic!` needed in each crate: one `podnet_core::io_macros!()` that defines them at the crate root, or a copy (25 lines) |
| Build info | `build.rs` sets `CFRS_BUILD_COMMIT`, `CFRS_BUILD_TARGET`, `CFRS_BUILD_DATE` | `fetch.rs` and `report.rs` (core), `config.rs`, `quicktunnel.rs`, `tunnel.rs` (cloudflare) read `CARGO_PKG_VERSION`/`CFRS_BUILD_COMMIT`: give the core a `build.rs` too, or a `version()` that the binary sets at start |
| Versions | one bump | `version.workspace = true` in each crate; path dependencies with the workspace version (the #222 rule of `pod-netns` applies to each) |
| Publish | ruling of 2026-11-04: publish nothing now | the same ruling; a later publish needs 8 names |

Recommendation: do steps A to C (sections 4.6) in any case. They give the
maintainability goal, and they make the crate split a mechanical step.
Then extract the crates (step E). Reasons: the adapter model of the goal
maps to crates, the compiler keeps the layers, the build of one adapter
does not rebuild the others, and future heavy adapters stay optional.
Keep the count at 8 (+ testkit): a crate for each small module adds
manifests, versions and packaging work and gives nothing. Measure
before and after with `cargo build --timings` and a touch-and-rebuild of
`src/cli/cmd/warp/up.rs` and of `crates/podnet-core/src/egress/mod.rs`.

### 4.3 Network adapters: traits and registry

A network gives egress (a way out for TCP and UDP flows), ingress (a way
in to local services), exports (a configuration for another program), or
a mix. Today's code already has each part, with no common interface:

| Network | Egress | Ingress | Export | Code today |
| --- | --- | --- | --- | --- |
| direct | `egress::dial` direct, kernel UDP | local listener (`serve --local`) | - | `egress`, `net` |
| proxy (http, socks5, socks5h, unix, +exec) | `egress::Proxy::connect` | - | proxy variables | `egress`, `proxy_auth` |
| Cloudflare tunnel (quick, named) | - | public HTTPS URL, WebSocket forward | - | `tunnel`, `quicktunnel`, `edge_h2`, `proxy` |
| WARP (MASQUE h2/h3, WireGuard, carry) | `WarpStack::tcp_connect`, `UdpConn` | - | WireGuard (`warp export`), env, ssh-config, SOCKS front door, kernel TUN | `warp/` |
| WebSocket relay | TCP to ip:port (edge leg, MASQUE) | `relay node` / `relay connect` | - | `ws_relay`, `relay_reverse` |
| vnet | `NetStack` TCP/UDP | listener on a virtual subnet, switch | shim environment | `vnet/` |
| tailnet front door | `pod_netns::tailscale::Dialer` (ts-dial over the LocalAPI) | - | `net ts-shims` | `pod-netns`, `vnet::tailscale_ssh` |
| pod (consumer) | puts a program behind a dialer chain | inbound unix sockets | - | `pod-netns` |
| multi-WAN (new) | a combinator over dialers | - | an mwan JSON (FR of the lab kit) | - |

Proposed traits (in `podnet-core/src/network/`; the futures are boxed for
`dyn` use; no new dependency: `futures` is already one):

```rust
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The target of a flow: a name that the network resolves, or an address.
pub enum Target { Name { host: String, port: u16 }, Addr(SocketAddr) }

/// A way out. Implemented by Direct, Proxy, Warp (WarpStack), Relay (TCP
/// only), Upstream (pod_netns chains, tailnet), Vnet (NetStack), and the
/// combinators below.
pub trait Dialer: Send + Sync {
    fn label(&self) -> String;                         // log lines, `decisions`
    fn tcp<'a>(&'a self, to: &'a Target) -> BoxFuture<'a, anyhow::Result<BoxedIo>>;
    fn udp<'a>(&'a self) -> BoxFuture<'a, anyhow::Result<Box<dyn Datagrams>>> {
        Box::pin(async { anyhow::bail!("{} carries no UDP", self.label()) })
    }
    fn names_inside(&self) -> bool { false }           // socks5h: send the name
}

/// Poll-based datagrams, so that a quinn `AsyncUdpSocket` can wrap them
/// (today `warp::quic::WarpUdpSocket` does this for WarpStack only).
pub trait Datagrams: Send + Sync {
    fn poll_send_to(&self, cx: &mut Context<'_>, buf: &[u8], to: SocketAddr) -> Poll<io::Result<usize>>;
    fn poll_recv_from(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<(usize, SocketAddr)>>;
}

/// An adapter. `up` makes the network ready (register, handshake, bind).
pub trait Network: Send + Sync {
    fn scheme(&self) -> &'static str;                  // "warp", "relay", "wg", "proxy", "direct", "vnet", "tailscale"
    fn caps(&self) -> Caps;                            // EGRESS_TCP | EGRESS_UDP | INGRESS | EXPORT | KERNEL_IFACE
    fn up<'a>(&'a self, ctx: &'a Ctx) -> BoxFuture<'a, anyhow::Result<Link>>;
    fn checks(&self) -> Vec<Check> { Vec::new() }      // rows of `podnet doctor`
}

pub struct Link {
    pub dialer: Option<Arc<dyn Dialer>>,
    pub exports: Vec<Export>,                          // wg-quick file, env, ssh-config, mwan JSON
    pub status: serde_json::Value,                     // the ready document part
    pub close: Box<dyn FnOnce() -> BoxFuture<'static, ()> + Send>,
}

/// One row of the registry. The binary holds the table: no `inventory` or
/// `linkme` (no dependency, explicit order, static musl builds).
pub struct NetworkSpec {
    pub scheme: &'static str,
    pub about: &'static str,
    pub parse: fn(spec: &str, ctx: &Ctx) -> anyhow::Result<Box<dyn Network>>,
}
```

Combinators in core: `Chain` (an outer dialer carries an inner one: MASQUE
over the relay over a proxy, today `warp::Dial` and `MasqueOptions`),
`Rules` (a dialer for each target: `warp proxy -r`, `pod-netns -r`,
`NO_PROXY`), `Race` (today `race::race`, staggered), `Failover`, and
`Balance` (multi-WAN: weights, a TCP health check for each link as the FR
asks, flows kept on one link). `Balance` works with no CAP_NET_ADMIN (it
balances flows of the userspace stacks). The kernel form (one TUN per link,
policy routes, ECMP, as the `mwan` experiment does) is a later `router`
service for a host with root, behind the same `Network` list.

Registry in the binary: `podnet::networks() -> &'static [NetworkSpec]`,
one row for each enabled crate (cargo features `warp`, `cloudflare`,
`relay`, `vnet`, later `tailscale`, `firezone`). Spec strings follow the
`pod-netns -x` form: `direct`, `socks5h://...`, `http+exec:CMD`, `warp`,
`warp:identity=PATH`, `relay:HOST`, `wg:FILE`, `tailscale:/PATH/tailscaled.sock`.
Today's flags stay as aliases (parity): `--proxy`, `--no-proxy`,
`tunnel --transport auto|direct|warp|relay`, `warp --transport`,
`warp --carry`, `pod -x`/`-r`.

Ingress and services (in `podnet-serve`, because they need `axum`):

```rust
pub trait Service: Send + Sync {
    fn kind(&self) -> &'static str;                    // "files", "share", "forward", "hello", "status", "metrics"; later "git", "router", "socks"
    fn http(&self) -> Option<axum::Router> { None }
    fn stream<'a>(&'a self, io: BoxedIo, peer: Peer) -> BoxFuture<'a, anyhow::Result<()>>;
}

/// Ordered rules (host, path regex) to services: today's `Ingress` +
/// `ServiceRuntime`.
pub struct Services { /* rules: Vec<(Match, Arc<dyn Service>)> */ }

pub trait Ingress: Send + Sync {
    fn publish<'a>(&'a self, services: Arc<Services>, opts: &'a Publish)
        -> BoxFuture<'a, anyhow::Result<Box<dyn Published>>>;
}

pub trait Published: Send + Sync {
    fn url(&self) -> Option<String>;
    fn ready(&self) -> serde_json::Value;              // the --json / --detach document
    fn shutdown(self: Box<Self>) -> BoxFuture<'static, ()>;
}
```

Implementors: `CloudflareIngress` (wraps `TunnelBuilder`), `LocalIngress`
(`serve --local`, TCP or `unix:`), `RelayIngress` (`relay node`),
`VnetIngress` (a listener on a virtual subnet); later a tailnet ingress.
Keep today's `service::Built` enum as the implementation of the built-in
services (an exhaustive `match` is a check); the trait is the boundary for
new service crates (git hosting, router). The binary holds a second
registry of ingress networks.

Add the traits after the crate split (step F), first as wrappers of the
existing APIs, with no change of behaviour; then let the commands use
them.

### 4.4 Names that a rename touches (inputs for the rename study)

`CFRS_*` variables (47 names in the manual), `CFRSNET_*`/`CFRSSOCKS_*` and
`libcfrsnet.so`/`libcfrssocks.so`, the state directory
`$XDG_STATE_HOME/cfrs`, `cfrs-<uid>` in the temporary directory, the
systemd unit prefix `cfrs-`, the marker `>>> cfrs warp up >>>`, the
WebSocket forward default path `/__cfrs/ws` (`ws::DEFAULT_PATH`; seen on
the wire by older `connect` clients), the key `"cfrs"` in each JSON
document (E3), the release asset names `cfrs-<target>` that `cfrs update`
downloads, `CFRS_REPO`, `CFRS_BUILD_COMMIT`, `POD_NETNS_QUIET`,
`POD_NETNS_TEST_MEM`, the program name `cfrs pod`.

### 4.5 Library paths after the split

The facade keeps each module path: `pub use podnet_core::{exit, state,
egress, ...};`, `pub use podnet_warp as warp;`, `pub use podnet_vnet as
vnet;`, and the root re-exports of `src/lib.rs`. A `pub use other::module;`
also keeps `crate::module::Item` valid inside the root crate, so the code
that stays in the root needs few edits at each extraction. The rename
changes `cfrs::` to `podnet::` (breaking; release note `## Breaking`).

### 4.6 Order of steps (each commit green)

Each commit runs `sh scripts/agent/check.sh` (fmt, clippy
`-D warnings`, tests), keeps the test count, and updates the paths in the
documents. Commit and push after each step (`CLAUDE.md`).

A. Guards (no change of behaviour)
1. `scripts/agent/parity-snapshot.sh`: writes `man --json` command tree,
   the sorted public item list (`cargo doc`, `all.html`), and the test list
   to a directory; a second run diffs. Keep it in `scripts/agent/`.
2. `scripts/check-size.py` (limit 800, an allowlist of today's 32 files
   that may only shrink) and `scripts/check-layers.py` (the layer table of
   3.2, an allowlist of today's 18 edges that may only shrink). Add both to
   `check.sh` and `ci.yml`. Plant a defect in each once
   (`docs/development.md` rule).

B. File splits inside the crate (rename-neutral; one file per commit)
3. Tests out of the 9 files of 2.3 (one commit).
4. `src/main.rs` to `src/cli/` (8 commits, order in 2.1).
5. The 18 files of 2.2, lowest layer first: `egress`, `detach`, `update`,
   `doctor`, `vnet/stack`, `warp/ip`, `warp/session`, `warp/wg`,
   `warp/mod`, `warp/proxy`, `relay_reverse`, `share`, `feature`, `proxy`,
   `edge_h2`, `tunnel`, pod-netns `seccomp`, pod-netns `netns`.
6. The 4 test files of 2.4.

C. Cut the 18 edges of 3.3 (one commit for each row or pair of rows);
   the allowlist of `check-layers.py` becomes empty.

D. Rename `cfrs` to `podnet` (package, binary, library, documents,
   workflows; the compatibility rulings of 4.4). Separate commits, no
   moves in them: `git log --follow` and the reviews stay readable.

E. Crate extraction, bottom-up (one crate per commit): `podnet-testkit`;
   `crates/pod-netns` to `crates/podnet-netns`; `podnet-core`;
   `podnet-vnet` (with `shim/`); `podnet-relay`; `podnet-warp`;
   `podnet-serve`; `podnet-cloudflare`; the root becomes the CLI + facade.
   In each commit: the new `Cargo.toml` (subset of the dependencies), the
   facade `pub use`, `pub(crate)` to `pub` (with `#[doc(hidden)]`) only
   where a higher crate needs it, the macros, the env scan directories,
   the `cargo package --list` list of `ci.yml`, the MSRV check, the
   documents (`docs/maintenance.md` "The code" table), `fuzz/Cargo.toml`
   and `fuzz/Cargo.lock`.

F. Traits and registry (4.3): wrappers first (Direct, Proxy, Warp, Relay,
   Upstream, Vnet dialers; Cloudflare, Local, Relay ingress), then
   `Chain`/`Rules`/`Race`/`Balance`, then the commands. New adapters
   (generic WireGuard peer from `warp/wg.rs`, multi-WAN, Tailscale,
   Firezone) come after F, each as an own crate or module.

Evidence for each step: the checks of `check.sh`; the parity snapshot
diff (empty for B, C, E; only names for D); a `live.yml` run after each
commit that touches `warp/`, `tunnel`, `edge_h2`, `proxy`, `relay_reverse`,
`ws_relay` or `crates/pod-netns` (section 14 of the checklist: these
commands have no loopback test of the command).

## 5. Parity inventory

`study/parity-checklist.md` (1 088 lines, about 590 check boxes) has:

1. The 8 global options.
2. 19 behaviours of `main()` before and after the parse (pod pass-through,
   cloudflared compatibility and its 12 refused flags, token files, usage
   errors and hints, help groups and examples, rlimit, `--detach` rules,
   `--ca-file`, SIGPIPE, log level and colours, the foreground hint,
   signals, the failure report, the write-safe print macros).
3. 63 commands with their 316 own flags and arguments (defaults, `env`,
   values), the integration tests that run each command, the `src/main.rs`
   unit tests, and the live steps.
4. The `pod-netns` CLI (hand-written parser, `crates/pod-netns/src/cli.rs`).
5. The 58 entries of `manual::facts::ENVIRONMENT`.
6. 17 file entries (11 of the manual + 6 more: carry, export, relay
   caches, autostart, run directory, marker blocks, shims).
7. The 8 exit codes.
8. 30 JSON documents with their producer and their pins.
9. The 29 examples of the manual.
10. The library surface (1 127 items in 52 modules, root re-exports, the
    library-only subsystem, the `pod_netns` API).
11. Unit tests by module (751 in `src/`, 43 in `crates/pod-netns/src`) and
    the 210 integration tests.
12. The 46 steps of `live.yml` with their commands and checks.
13. The other gates (ci.yml jobs, release, update path, 16 fuzz targets,
    deny, secrets, upstream, docs tests, install script).
14. The commands with no behaviour test.

Tests that pin each area:

| Area | Pins |
| --- | --- |
| Command tree and flags (existence, docs) | `src/main.rs`: `the_command_tree_is_valid`, `each_help_screen_passes_the_lint`, `the_manual_names_each_command_and_flag`, `each_example_of_the_manual_parses`, `each_command_is_in_one_help_group`, `the_help_of_a_command_has_its_examples`; `tests/cli.rs::the_man_page_names_each_flag` |
| Exit codes and usage errors | `tests/cli.rs` (14 tests), `exit.rs` unit tests, `tests/detach.rs` (124, 75), `crates/pod-netns/tests/usage.rs`, live L487 (69) |
| Environment variables | `manual::facts` (`each_variable_in_the_source_is_in_the_manual`, `each_variable_in_the_manual_is_read_by_the_source`), `tests/cli.rs::the_environment_is_checked_alike` |
| JSON documents | `tests/cli.rs::json_documents_have_the_schema_and_the_version` (ps, ports, status), `log_format_json_gives_json_lines_only`, unit tests of `status`, `report`, `doctor`, `agent`; live L78, L100, L132, L398, L525, L549, L623, L684 (jq checks) |
| Detach, ps, logs, stop, wait | `tests/detach.rs` (20), `tests/connect.rs`, live L132, L398, L623, L684 |
| Egress, proxy, TLS roots | `tests/egress.rs` (8), `tests/tls.rs` (3), `tests/doctor.rs` (3), `tests/connect.rs` (5), unit tests of `egress` (17), `resolve` (9), `trust` (7); live L199, L248, L283 |
| Tunnel legs and edge protocol | unit tests of `cloudflare/` (66), `edge_h2` (18), `proxy` (19), `tunnel` (10), `quicktunnel` (20), `race` (6); live L94-L381 |
| WARP | unit tests of `warp/` (140); live L446-L924 and `scripts/live-batch2.sh` (the only command-level proof) |
| Relay | `tests/relay_reverse.rs` (10, library level), unit tests of `ws_relay` (7), `relay_pool` (5), `relay_reverse` (8); live L381, L398, L510 |
| vnet and shims | unit tests of `vnet/` (84), `tests/shim_direct.rs` (11), `shim_no_socket.rs` (6), `shim_socks.rs` (1), `af_inet_kernel.rs` (4), `vnet_regressions.rs` (8), `vnet_proxy_forward.rs` (1), `tcp_window.rs` (1) |
| pod backends | `crates/pod-netns/tests/seccomp.rs` (30), `raw.rs` (1), `usage.rs` (3), 43 unit tests; live L656, L753; `scripts/test_in_box.sh` (L915) |
| Library shapes | `tests/api_surface.rs` (2), `cargo doc -D warnings` (ci.yml), `cargo package --list` (ci.yml) |
| Documents and releases | `tests/docs.rs` (11) |
| Install script | `tests/install_script.rs` (23) |

Gaps (no behaviour test of the command, only the always-on pins):
`bug-report`, `qr`, `net demo`, `warp license`, `warp rotate`,
`warp shell`, `autostart run`, `agent status`, `wait` (no live step).
Live-only: `warp register`, `status`, `exit`, `export`, `forward`, `tun`,
`run`, `proxy`, `relay pair`. Add a loopback test for the first group
before step B4, or record the risk.

## 6. Questions for the owner

1. Binaries: only `podnet`, or also a `cfrs` name (symlink or argv[0])
   for one release? Keep the `pod-netns` binary and release asset, or
   rename it `podnet-netns`?
2. Compatibility of the names of 4.4: `PODNET_*` with `CFRS_*` read as
   aliases (how long?); the state directory (read the old one, or move it
   at the first run); the JSON key `"cfrs"` (rename, or both for one
   release); `/__cfrs/ws` (wire-visible); the shim names.
3. The library-only subsystem (`feature`, `origin`, `transport`, `relay`,
   about 5 600 lines, no caller in the binary): keep it in `podnet-serve`
   (this study assumes yes, by the parity rule)?
4. File-size limit: 800 (this study) or 500 (the podssh rule, 29 more
   files)? Enforce it with `scripts/check-size.py`?
5. The 8 crates and their names, and the root package as the `podnet`
   CLI + facade: accept?
6. Order: in-crate splits (A-C) under the name `cfrs`, then the rename,
   then the crate extraction (recommended), or the rename first?
7. Step F changes the command line (a `--via SPEC` form): keep each old
   flag as an alias, with no removal (assumed by the parity rule)?

## Appendix A. Every `.rs` file (lines; flag: over 800)

| File | Lines | Flag |
| --- | --- | --- |
| `crates/pod-netns/build.rs` | 7 |  |
| `crates/pod-netns/src/cli.rs` | 258 |  |
| `crates/pod-netns/src/dns.rs` | 259 |  |
| `crates/pod-netns/src/doctor.rs` | 377 |  |
| `crates/pod-netns/src/fakedns.rs` | 111 |  |
| `crates/pod-netns/src/frontdoor.rs` | 272 |  |
| `crates/pod-netns/src/inbox.rs` | 503 |  |
| `crates/pod-netns/src/lib.rs` | 456 |  |
| `crates/pod-netns/src/listen.rs` | 225 |  |
| `crates/pod-netns/src/main.rs` | 8 |  |
| `crates/pod-netns/src/netns.rs` | 1199 | **>800** |
| `crates/pod-netns/src/raw.rs` | 436 |  |
| `crates/pod-netns/src/seccomp.rs` | 1900 | **>800** |
| `crates/pod-netns/src/socks.rs` | 746 |  |
| `crates/pod-netns/src/tailscale.rs` | 556 |  |
| `crates/pod-netns/src/upstream.rs` | 1040 | **>800** |
| `crates/pod-netns/tests/raw.rs` | 87 |  |
| `crates/pod-netns/tests/seccomp.rs` | 2018 | **>800** |
| `crates/pod-netns/tests/usage.rs` | 96 |  |
| `fuzz/fuzz_targets/acl_rule.rs` | 3 |  |
| `fuzz/fuzz_targets/capnp_message.rs` | 3 |  |
| `fuzz/fuzz_targets/capsule.rs` | 3 |  |
| `fuzz/fuzz_targets/config_yaml.rs` | 3 |  |
| `fuzz/fuzz_targets/connect_request.rs` | 3 |  |
| `fuzz/fuzz_targets/connect_response_head.rs` | 3 |  |
| `fuzz/fuzz_targets/doh_json.rs` | 3 |  |
| `fuzz/fuzz_targets/h2_header_block.rs` | 3 |  |
| `fuzz/fuzz_targets/ingress_rule.rs` | 3 |  |
| `fuzz/fuzz_targets/no_proxy.rs` | 3 |  |
| `fuzz/fuzz_targets/proxy_url.rs` | 3 |  |
| `fuzz/fuzz_targets/register_response.rs` | 3 |  |
| `fuzz/fuzz_targets/request_head.rs` | 3 |  |
| `fuzz/fuzz_targets/rpc_message.rs` | 3 |  |
| `fuzz/fuzz_targets/srv_record.rs` | 3 |  |
| `fuzz/fuzz_targets/vnet_frame.rs` | 3 |  |
| `fuzz/src/seed.rs` | 14 |  |
| `src/agent.rs` | 692 |  |
| `src/autostart.rs` | 791 |  |
| `src/bug_report.rs` | 200 |  |
| `src/cloudflare/capnp.rs` | 944 | **>800** |
| `src/cloudflare/http2.rs` | 1123 | **>800** |
| `src/cloudflare/mod.rs` | 450 |  |
| `src/cloudflare/quic.rs` | 251 |  |
| `src/cloudflare/rpc.rs` | 691 |  |
| `src/cloudflare/schema.rs` | 352 |  |
| `src/cloudflare/stream.rs` | 145 |  |
| `src/config.rs` | 1204 | **>800** |
| `src/connect.rs` | 338 |  |
| `src/decisions.rs` | 96 |  |
| `src/detach.rs` | 1210 | **>800** |
| `src/doctor.rs` | 1309 | **>800** |
| `src/edge_discovery.rs` | 314 |  |
| `src/edge_h2.rs` | 1736 | **>800** |
| `src/egress.rs` | 1707 | **>800** |
| `src/exit.rs` | 203 |  |
| `src/feature/mod.rs` | 2139 | **>800** |
| `src/fetch.rs` | 548 |  |
| `src/fuzzing.rs` | 363 |  |
| `src/gate.rs` | 478 |  |
| `src/hop.rs` | 210 |  |
| `src/ingress.rs` | 580 |  |
| `src/instances.rs` | 636 |  |
| `src/lib.rs` | 150 |  |
| `src/main.rs` | 7103 | **>800** |
| `src/manual/facts.rs` | 610 |  |
| `src/manual/mod.rs` | 270 |  |
| `src/manual/model.rs` | 235 |  |
| `src/manual/pager.rs` | 120 |  |
| `src/manual/roff.rs` | 145 |  |
| `src/manual/text.rs` | 247 |  |
| `src/metrics.rs` | 135 |  |
| `src/net.rs` | 403 |  |
| `src/origin/mod.rs` | 420 |  |
| `src/origin/static_files.rs` | 608 |  |
| `src/origin/tcp.rs` | 222 |  |
| `src/origin/unix_socket.rs` | 71 |  |
| `src/ports.rs` | 129 |  |
| `src/preflight.rs` | 656 |  |
| `src/proxy.rs` | 2034 | **>800** |
| `src/proxy_auth.rs` | 615 |  |
| `src/qr.rs` | 119 |  |
| `src/quicktunnel.rs` | 892 | **>800** |
| `src/race.rs` | 257 |  |
| `src/relay.rs` | 668 |  |
| `src/relay_pool.rs` | 380 |  |
| `src/relay_reverse.rs` | 1139 | **>800** |
| `src/report.rs` | 612 |  |
| `src/resolve.rs` | 591 |  |
| `src/rlimit.rs` | 98 |  |
| `src/service.rs` | 326 |  |
| `src/share.rs` | 1901 | **>800** |
| `src/state.rs` | 583 |  |
| `src/status.rs` | 202 |  |
| `src/tls_fragment.rs` | 397 |  |
| `src/transport/mod.rs` | 492 |  |
| `src/transport/ssh.rs` | 342 |  |
| `src/transport/websocket.rs` | 510 |  |
| `src/trust.rs` | 495 |  |
| `src/tunnel.rs` | 1599 | **>800** |
| `src/udp.rs` | 246 |  |
| `src/update.rs` | 1162 | **>800** |
| `src/util/http.rs` | 380 |  |
| `src/util/mod.rs` | 187 |  |
| `src/util/tls.rs` | 146 |  |
| `src/vnet/addr.rs` | 581 |  |
| `src/vnet/control.rs` | 670 |  |
| `src/vnet/device.rs` | 639 |  |
| `src/vnet/dns.rs` | 272 |  |
| `src/vnet/doctor.rs` | 672 |  |
| `src/vnet/framing.rs` | 253 |  |
| `src/vnet/mod.rs` | 74 |  |
| `src/vnet/policy.rs` | 392 |  |
| `src/vnet/proxy.rs` | 514 |  |
| `src/vnet/record.rs` | 362 |  |
| `src/vnet/shim.rs` | 459 |  |
| `src/vnet/stack.rs` | 2103 | **>800** |
| `src/vnet/switch.rs` | 1072 | **>800** |
| `src/vnet/tailscale_ssh.rs` | 331 |  |
| `src/warp/capsule.rs` | 301 |  |
| `src/warp/exit.rs` | 273 |  |
| `src/warp/export.rs` | 362 |  |
| `src/warp/forward.rs` | 203 |  |
| `src/warp/h3.rs` | 622 |  |
| `src/warp/identity.rs` | 207 |  |
| `src/warp/ip.rs` | 1680 | **>800** |
| `src/warp/l4.rs` | 270 |  |
| `src/warp/live.rs` | 493 |  |
| `src/warp/mod.rs` | 1105 | **>800** |
| `src/warp/nc.rs` | 462 |  |
| `src/warp/proxy.rs` | 1991 | **>800** |
| `src/warp/quic.rs` | 296 |  |
| `src/warp/register.rs` | 936 | **>800** |
| `src/warp/route.rs` | 790 |  |
| `src/warp/rules.rs` | 430 |  |
| `src/warp/session.rs` | 1211 | **>800** |
| `src/warp/ssh_config.rs` | 376 |  |
| `src/warp/tun.rs` | 361 |  |
| `src/warp/up.rs` | 1043 | **>800** |
| `src/warp/wg.rs` | 1078 | **>800** |
| `src/ws.rs` | 596 |  |
| `src/ws_relay.rs` | 995 | **>800** |
| `src/yaml.rs` | 530 |  |
| `tests/af_inet_kernel.rs` | 170 |  |
| `tests/afinet_audit/mod.rs` | 238 |  |
| `tests/api_surface.rs` | 89 |  |
| `tests/cli.rs` | 2305 | **>800** |
| `tests/connect.rs` | 367 |  |
| `tests/detach.rs` | 812 | **>800** |
| `tests/docs.rs` | 312 |  |
| `tests/doctor.rs` | 238 |  |
| `tests/egress.rs` | 444 |  |
| `tests/install_script.rs` | 670 |  |
| `tests/relay_reverse.rs` | 568 |  |
| `tests/shim_direct.rs` | 822 | **>800** |
| `tests/shim_no_socket.rs` | 349 |  |
| `tests/shim_socks.rs` | 141 |  |
| `tests/signals.rs` | 196 |  |
| `tests/tcp_window.rs` | 146 |  |
| `tests/test_host/mod.rs` | 104 |  |
| `tests/tls.rs` | 190 |  |
| `tests/update_umask.rs` | 21 |  |
| `tests/vnet_proxy_forward.rs` | 96 |  |
| `tests/vnet_regressions.rs` | 308 |  |
