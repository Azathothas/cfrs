# Notice

This crate is derived from `cloudflare-quick-tunnel` 0.3.1
(<https://github.com/lordmacu/cloudflare-quick-tunnel-rs>), licensed under
the MIT license or the Apache License 2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`. The changes in this copy are in the git history of this
repository.

These files come from `cloudflared` (<https://github.com/cloudflare/cloudflared>),
licensed under the Apache License 2.0:

| Path | Source in cloudflared |
| --- | --- |
| `schemas/tunnelrpc.capnp` | `tunnelrpc/proto/tunnelrpc.capnp` |
| `schemas/quic_metadata_protocol.capnp` | `tunnelrpc/proto/quic_metadata_protocol.capnp` |
| `schemas/go.capnp` | `tunnelrpc/proto/go.capnp` |
| `cf-edge-roots.pem` | `tlsconfig/cloudflare_ca.go` (`cloudflareRootCA`) |
