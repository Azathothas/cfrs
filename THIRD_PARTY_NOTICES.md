# Third-party notices

`cfrs` is 0BSD (see `LICENSE`). These parts have other licenses:

| Path | Origin | License |
| --- | --- | --- |
| `crates/cfrs-edge/` | Derived from `cloudflare-quick-tunnel` 0.3.1 (<https://github.com/lordmacu/cloudflare-quick-tunnel-rs>) | MIT or Apache-2.0. See `crates/cfrs-edge/LICENSE-MIT`, `crates/cfrs-edge/LICENSE-APACHE` and `crates/cfrs-edge/NOTICE.md`. |
| `crates/cfrs-edge/schemas/*.capnp` | `cloudflared` (<https://github.com/cloudflare/cloudflared>) | Apache-2.0 |
| `crates/cfrs-edge/cf-edge-roots.pem`, `src/cloudflare/cf-edge-roots.pem` | `cloudflared`, `tlsconfig/cloudflare_ca.go` | Apache-2.0 |
| `tools/header-oracle.txt`, the Go program in `tools/check-header-oracle.sh` | `cloudflared`, `connection/header.go` (`SerializeHeaders`) | Apache-2.0 |

The Rust dependencies are listed in `Cargo.lock`. Each has its own license.
