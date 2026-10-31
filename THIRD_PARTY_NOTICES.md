# Third-party notices

`cfrs` is 0BSD (see `LICENSE`). These files are from `cloudflared`
(<https://github.com/cloudflare/cloudflared>) and have the Apache License 2.0:

| Path | Source in cloudflared |
| --- | --- |
| `src/cloudflare/schemas/tunnelrpc.capnp` | `tunnelrpc/proto/tunnelrpc.capnp` |
| `src/cloudflare/schemas/quic_metadata_protocol.capnp` | `tunnelrpc/proto/quic_metadata_protocol.capnp` |
| `src/cloudflare/cf-edge-roots.pem` | `tlsconfig/cloudflare_ca.go` (`cloudflareRootCA`) |
| `tools/header-oracle.txt`, the Go program in `tools/check-header-oracle.sh` | `connection/header.go` (`SerializeHeaders`) |

The schemas are the wire format. `cfrs` does not compile them: the layouts in
`src/cloudflare/schema.rs` follow from them.

The Rust dependencies are listed in `Cargo.lock`. Each has its own license.
