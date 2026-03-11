# Vanta CLI Guide

`vanta-cli` is the operator-facing entrypoint for the canonical Rust workspace. It exposes helpers for key generation, registry compilation, frame inspection, audit verification, transcript hashing, and running the reference daemon.

## Build and invoke

From the workspace root:

```bash
cd vanta-rs
cargo run -p vanta-cli -- --help
```

You can also build a reusable binary:

```bash
cargo build -p vanta-cli
./target/debug/vanta-cli --help
```

## What the CLI can do

- Create a new Ed25519 identity and print its `PeerID`
- Compile a JSON registry manifest into canonical schema/capability tokens
- Decode and pretty-print a binary or hex-encoded Vanta frame
- Generate canonical sample frames for tests, docs, or local experiments
- Verify an encoded audit receipt and print the resulting receipt hash
- Compute the canonical transcript hash used by the handshake code
- Start the reference daemon from a TOML config file

## Global help

Sample command:

```bash
cargo run -p vanta-cli -- --help
```

Example output:

```text
Vanta v0 reference operator CLI

Usage: vanta-cli <COMMAND>

Commands:
  keygen
  compile-registry
  inspect-frame
  verify-audit
  transcript-hash
  run-daemon
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

## Command Reference

### `keygen`

Purpose:

- Generates a new Ed25519 identity keypair
- Prints the derived `PeerID`
- Prints the base64-encoded private signing seed used by the reference implementation

Sample command:

```bash
cargo run -p vanta-cli -- keygen
```

Example output:

```text
peer_id=9d7d6a4f...<32-byte hex omitted>...
signing_key_base64=8l5h2Q8g...<base64 seed omitted>...
```

Notes:

- Output changes on every run because the keypair is randomly generated.
- Store the `signing_key_base64` value securely. It is sufficient to recreate the node identity.

### `compile-registry`

Purpose:

- Reads a JSON registry manifest
- Canonicalizes schema and capability descriptors
- Derives `SchemaToken` and `CapabilityToken`
- Prints the compiled registry as pretty JSON

Input file:

- Use [`examples/demo-registry.json`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/examples/demo-registry.json) as a starting point.

Sample command:

```bash
cargo run -p vanta-cli -- compile-registry examples/demo-registry.json
```

Example output:

```json
{
  "name": "demo",
  "version": 1,
  "schema_token": 1098448329,
  "capability_token": 841132702,
  "extension_namespaces": [
    "vanta.core",
    "demo.app"
  ],
  "schemas": [
    {
      "family_id": [1,2,3,4,5,6,7,8],
      "version_id": 1,
      "name": "demo.command",
      "descriptor_hash_hex": "1e29e4dc9a694a80724cbd69c47a5f8dbcd4e6f58525d9886331b1217874d89c"
    }
  ],
  "capabilities": [
    {
      "capability_id": [17,18,19,20,21,22,23,24],
      "name": "mutate",
      "descriptor_hash_hex": "2e0f26c8fc2ab487f66a5520ccc5463ca46cf27a0fcfae1f6e794a72c0130ea5"
    }
  ]
}
```

When to use it:

- Before running the daemon with a new schema/capability set
- To confirm token stability after changing registry inputs
- To inspect descriptor hashes during interoperability work

### `inspect-frame`

Purpose:

- Reads either a raw binary frame or a text file containing hex bytes
- Decodes the base header, extension block, payload bytes, and optional AEAD tag
- Prints the result with Rust `Debug` formatting
- Can also generate sample `hello`, `request`, `command`, or `heartbeat` frames

Decode an existing hex file:

```bash
cargo run -p vanta-cli -- inspect-frame capture.hex --hex
```

Generate a sample request frame as hex on stdout:

```bash
cargo run -p vanta-cli -- inspect-frame --sample request --hex
```

Generate a sample command frame into a file:

```bash
cargo run -p vanta-cli -- inspect-frame --sample command --output examples/request-frame.hex --hex
```

Example output when generating a sample:

```text
56545031000000620000007000121204ec9590781111111111111111111111111111111101000000000000003333333333333333333333333333333300000000000000010000000e418000113220001182102222222222222222222222222222222273616d706c652d636f6d6d616e64
generated sample Command
Frame {
    header: BaseHeader {
        major_version: 0,
        minor_version: 0,
        header_length: 98,
        frame_length: 112,
        extension_length: 18,
        frame_type: Command,
        flags: ACK_REQ,
        ...
    },
    extensions: [
        Extension { ... }
    ],
    payload: b"sample-command",
    aead_tag: None,
}
```

Use `--hex` when:

- decoding a text file that contains hex bytes
- generating a text file instead of a raw binary file

Rules:

- `inspect-frame <input>` decodes an existing frame
- `inspect-frame --sample <kind>` generates a new sample frame
- `--output <path>` is optional during generation; without it, the encoded frame is printed to stdout as hex

### `verify-audit`

Purpose:

- Decodes an encoded `AUDIT_RECEIPT`
- Recomputes the canonical receipt hash
- Verifies the receipt signature using the receiver `PeerID`
- Prints the resulting hash if verification succeeds

Sample command:

```bash
cargo run -p vanta-cli -- verify-audit receipt.bin --previous-hash-hex 0000000000000000000000000000000000000000000000000000000000000000
```

Example output:

```text
receipt_hash=4d2a0e4bb0a1f8b8c5f2...<32-byte hash omitted>...
```

Operational notes:

- `--previous-hash-hex` is optional. If omitted, the tool uses the receipt’s embedded `prev_receipt_hash`.
- Signature verification failure exits the command with an error.

### `transcript-hash`

Purpose:

- Computes the canonical transcript hash used by the handshake code
- Accepts one or more message fragments as command-line strings

Sample command:

```bash
cargo run -p vanta-cli -- transcript-hash hello world
```

Example output:

```text
c0f14902b006694c74a5cb9cd7f9531cb66aed56eee8022044d440b3d2c56c6a
```

Useful for:

- Comparing transcript behavior during interop debugging
- Checking that two peers are hashing the same handshake messages
- Generating deterministic vectors for docs and tests

### `run-daemon`

Purpose:

- Loads a TOML config file
- Opens the durable SQLite backend
- Starts the reference daemon as an endpoint or relay
- Serves configured TCP, WebSocket, and Unix socket listeners

Input file:

- Use [`examples/daemon.toml`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/examples/daemon.toml) as a template.

Sample command:

```bash
cargo run -p vanta-cli -- run-daemon examples/daemon.toml
```

Example output:

```text
# no stdout on success; the daemon stays in the foreground and begins accepting connections
```

Operational notes:

- Successful startup is silent right now; errors are returned directly to the terminal.
- The current daemon implementation initiates and responds to the Vanta handshake, echoes requests, emits audit receipts for commands, and shares one session core across transport types.

## Typical workflows

### Bootstrap a fresh identity

```bash
cargo run -p vanta-cli -- keygen
```

Take the printed base64 seed and place it in your daemon config as `identity_seed_hex` after converting it to the hex format expected by the TOML config, or derive a hex seed directly in your provisioning step.

### Compile a registry before starting a node

```bash
cargo run -p vanta-cli -- compile-registry examples/demo-registry.json
```

Copy the resulting compiled registry block into your daemon config.

### Generate and inspect a sample frame

```bash
cargo run -p vanta-cli -- inspect-frame --sample hello --output /tmp/hello.hex --hex
cargo run -p vanta-cli -- inspect-frame /tmp/hello.hex --hex
```

### Investigate a captured frame

```bash
cargo run -p vanta-cli -- inspect-frame capture.bin
```

If the capture is stored as hex:

```bash
cargo run -p vanta-cli -- inspect-frame capture.hex --hex
```

### Verify an audit receipt from a test or peer log

```bash
cargo run -p vanta-cli -- verify-audit receipt.bin
```

## Current limitations

- `compile-registry` currently expects JSON input, not TOML.
- `run-daemon` expects a compiled registry embedded in the TOML config rather than a manifest path.
- `verify-audit` verifies a single receipt at a time rather than an entire chain directory.
