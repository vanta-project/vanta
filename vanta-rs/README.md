# vanta-rs

Canonical Rust reference implementation for Vanta v0.

## Quick Start

```bash
cd vanta-rs
cargo test
cargo run -p vanta-cli -- --help
```

## Workspace

- `vanta-wire`: wire types, frame codec, payload layouts, vectors
- `vanta-crypto`: identities, transcript hashing, key schedule, AEAD helpers
- `vanta-registry`: signed registry manifest compilation and token derivation
- `vanta-storage`: storage traits and SQLite-backed durable default
- `vanta-runtime`: session engine, public protocol/runtime traits, audit handling
- `vanta-transport`: TCP, WebSocket, Unix socket, and relay transport adapters
- `vanta-daemon`: runnable reference node and blind relay
- `vanta-cli`: operator CLI

## Docs

- [`docs/cli.md`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/docs/cli.md): CLI guide with command reference, examples, and output samples
- [`docs/v0-wire-supplement.md`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/docs/v0-wire-supplement.md): canonical wire decisions for the Rust implementation
- [`docs/conformance-matrix.md`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/docs/conformance-matrix.md): current spec-to-code mapping

## Examples

- [`examples/demo-registry.json`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/examples/demo-registry.json): sample signed-registry input for `compile-registry`
- [`examples/daemon.toml`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/examples/daemon.toml): sample daemon configuration
- [`examples/node-a.toml`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/examples/node-a.toml): sample node A configuration for two-node testing
- [`examples/node-b.toml`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/examples/node-b.toml): sample node B configuration for two-node testing

## Canonical v0 choices

- `HeaderLength` includes the fixed 80-byte base header and any TLV extensions.
- `FrameLength` covers the complete transmitted frame, including the AEAD tag when present.
- `PayloadLength` excludes the AEAD tag.
- Header CRC32C is calculated over the base header with the CRC field zeroed.
- The high bit of a TLV type marks the extension as critical.
- Schema and capability tokens are the first 32 bits of a SHA-256 digest over canonical registry descriptors.

See [`docs/v0-wire-supplement.md`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/docs/v0-wire-supplement.md) for the normative wire supplement used by the implementation.
