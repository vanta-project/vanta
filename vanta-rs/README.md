# vanta-rs

Canonical Rust reference implementation for Vanta v0.

## Workspace

- `vanta-wire`: wire types, frame codec, payload layouts, vectors
- `vanta-crypto`: identities, transcript hashing, key schedule, AEAD helpers
- `vanta-registry`: signed registry manifest compilation and token derivation
- `vanta-storage`: storage traits and SQLite-backed durable default
- `vanta-runtime`: session engine, public protocol/runtime traits, audit handling
- `vanta-transport`: TCP, WebSocket, Unix socket, and relay transport adapters
- `vanta-daemon`: runnable reference node and blind relay
- `vanta-cli`: operator CLI

## Canonical v0 choices

- `HeaderLength` includes the fixed 80-byte base header and any TLV extensions.
- `FrameLength` covers the complete transmitted frame, including the AEAD tag when present.
- `PayloadLength` excludes the AEAD tag.
- Header CRC32C is calculated over the base header with the CRC field zeroed.
- The high bit of a TLV type marks the extension as critical.
- Schema and capability tokens are the first 32 bits of a SHA-256 digest over canonical registry descriptors.

See [`docs/v0-wire-supplement.md`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/docs/v0-wire-supplement.md) for the normative wire supplement used by the implementation.
