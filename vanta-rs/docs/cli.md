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
- Generate a real signed sample audit receipt payload for verification workflows
- Start a sample initiator peer that can connect to the daemon and exercise request/command flows
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
  generate-audit
  run-peer
  run-node
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

Where `receipt.bin` comes from:

- In a live Vanta exchange, the reference daemon emits `AUDIT_RECEIPT` frames when it handles `COMMAND` frames.
- `verify-audit` expects the raw encoded receipt payload, not the full outer Vanta frame.
- The CLI does not yet have a dedicated `extract-audit-from-frame` helper, so the practical local workflow today is to generate a receipt payload with `generate-audit` or capture the payload bytes from an `AUDIT_RECEIPT` frame in your own test harness or transport trace.

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
- If you need a valid local input file, generate one first with `generate-audit --output receipt.bin`.

### `generate-audit`

Purpose:

- Generates a real signed `AUDIT_RECEIPT` payload using the same canonical binary encoding and signature verification path as the reference implementation
- Writes the encoded receipt to a file as raw binary or hex
- Prints the receiver `PeerID` and computed receipt hash

Sample command:

```bash
cargo run -p vanta-cli -- generate-audit --output receipt.bin
```

Hex output variant:

```bash
cargo run -p vanta-cli -- generate-audit --output receipt.hex --hex
```

Example output:

```text
wrote_receipt=receipt.bin
receiver_peer_id=d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48
receipt_hash=221cbb6e6fb0404e163a2f3c91d90db295ba7dc83e4c0ebed6b9fa7c8f536125
```

What it produces:

- A standalone encoded receipt payload suitable for `verify-audit`
- Not a full outer `AUDIT_RECEIPT` frame

Typical local workflow:

```bash
cargo run -p vanta-cli -- generate-audit --output receipt.bin
cargo run -p vanta-cli -- verify-audit receipt.bin
```

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

What happens when you run it:

- The command parses the TOML file into `DaemonConfig`
- The daemon opens or creates the SQLite database configured by `sqlite_path`
- It starts one listener task per configured transport
- For each accepted connection it creates a fresh Vanta session and immediately sends a `HELLO` frame
- It then runs the current reference session loop for that connection until the transport closes or the session errors

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

## What The Daemon Actually Does

If you start the sample config:

```bash
cd vanta-rs
cargo run -p vanta-cli -- run-daemon examples/daemon.toml
```

the following runtime behavior is available today.

### Listeners that come up

With the sample [`examples/daemon.toml`](/Users/benn/Documents/Projects/research/vanta-transfer-protocol/vanta-rs/examples/daemon.toml), the daemon starts:

- a TCP listener on `127.0.0.1:7401`
- a WebSocket listener on `127.0.0.1:7402`
- a Unix domain socket listener at `/tmp/vanta-demo.sock`

It also opens or creates:

- a SQLite WAL database at `vanta-demo.db`

That database is used by the reference storage layer for deduplication state, resume state, audit chain state, and registry cache.

### What a client can do

If a client already speaks the current Rust Vanta wire/runtime behavior, it can:

- connect over TCP, WebSocket, or Unix socket
- complete the current HELLO/AUTH/NEGOTIATE/CAPS handshake
- send `REQUEST` frames and receive `RESPONSE` frames
- send `COMMAND` frames with an `OperationID` extension and receive:
  - an `AUDIT_RECEIPT` frame
  - a `RESPONSE` frame carrying the applied or duplicate disposition
- send `FLOW_CREDIT`, `ACK`, `HEARTBEAT`, and related control traffic through the same session core

### What the daemon does for requests

For a `REQUEST` frame:

- it accepts the frame through the session runtime
- it treats the payload as opaque bytes
- it sends back a `RESPONSE` frame containing the same payload bytes

This is currently an echo-style reference behavior, not an application-specific service.

### What the daemon does for commands

For a `COMMAND` frame:

- it requires the runtime-level `OperationID` extension used by the current session implementation
- it records deduplication state in SQLite
- it computes and signs an audit receipt
- it emits that receipt inside an `AUDIT_RECEIPT` frame
- it sends a `RESPONSE` frame using the receipt’s disposition

The important effect is that repeated commands with the same `(PeerID, OperationID)` pair produce duplicate handling behavior through the runtime/storage layer.

### What the daemon does not do yet

Running `run-daemon` does not give you a complete application node yet. It does not currently:

- expose a higher-level application API on top of request/command payloads
- include a CLI client that connects to the daemon and speaks the live protocol
- extract audit receipt payloads from captured `AUDIT_RECEIPT` frames for you
- implement a true blind relay/routing plane even though `mode = "Relay"` exists
- provide graceful shutdown, structured logs, metrics, auth policy configuration, or production operational controls
- implement a general pub/sub or streaming application service on top of the stream/event frame types

### What `mode = "Relay"` means right now

`mode = "Relay"` currently changes the daemon’s session role to `Relay` during handshake construction, but it does not yet turn the daemon into a functioning multi-hop forwarder. In practice:

- `Endpoint` is the only meaningful mode for actual experimentation today
- `Relay` should be treated as scaffolded protocol shape, not a finished feature

### What you can do immediately after startup

Practical things you can do right now:

- keep the daemon running and connect a custom test client or integration harness to one of the configured listeners
- use the Rust crates directly to build a small local client against the live daemon
- inspect generated sample frames with `inspect-frame` to understand the wire shape before writing a client
- use `generate-audit` and `verify-audit` to understand the audit payload format independently of a live connection

What you cannot do entirely from the shipped CLI yet:

- send a real live `REQUEST` or `COMMAND` to the running daemon from the CLI itself
- fetch audit receipts back out of the daemon via a supported admin/API command

### Mental model

The current daemon is best understood as:

- a runnable reference transport/server shell
- backed by the real session runtime and durable storage
- useful for protocol bring-up, interop harnesses, and codec/runtime debugging
- not yet a feature-complete end-user node

### `run-peer`

Purpose:

- Starts a sample initiator peer process
- Connects to a running daemon using the same session runtime
- Completes the live handshake
- Sends either a `REQUEST` or `COMMAND`
- Prints the resulting `RESPONSE` and, for commands, the emitted `AUDIT_RECEIPT`

What it is for:

- Actually testing the current protocol implementation without writing your own client first
- Verifying that the daemon listeners and handshake work
- Exercising deduplication by repeating the same command with the same peer identity and `OperationID`

Sample request flow:

```bash
cargo run -p vanta-cli -- run-peer \
  --daemon-config examples/daemon.toml \
  --transport tcp \
  --action request \
  --payload hello-vanta
```

Sample command flow:

```bash
cargo run -p vanta-cli -- run-peer \
  --daemon-config examples/daemon.toml \
  --transport tcp \
  --action command \
  --payload mutate-once
```

Run the same command twice to exercise duplicate handling:

```bash
cargo run -p vanta-cli -- run-peer \
  --daemon-config examples/daemon.toml \
  --transport tcp \
  --action command \
  --payload mutate-once \
  --identity-seed-hex 7777777777777777777777777777777777777777777777777777777777777777 \
  --operation-id-hex 22222222222222222222222222222222

cargo run -p vanta-cli -- run-peer \
  --daemon-config examples/daemon.toml \
  --transport tcp \
  --action command \
  --payload mutate-once \
  --identity-seed-hex 7777777777777777777777777777777777777777777777777777777777777777 \
  --operation-id-hex 22222222222222222222222222222222
```

Expected behavior:

- first run: `audit disposition=Applied`
- second run: `audit disposition=DuplicateApplied`

Example output:

```text
peer_id=c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7
heartbeat ping_id=1048576 timestamp_millis=1773251959702
session_active schema_token=1098448329 capability_token=841132702
sent_Command message_id=50505050505050505050505050505050
audit disposition=Applied receipt_id=03e28622b9281ae3b0d39a13133e1e1c receiver_peer_id=8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
response disposition=Applied payload=mutate-once
session_id=3013677a832c4faee4ff6eeef0015c74
```

Transport support today:

- `--transport tcp`
- `--transport unix`

Current limitations:

- `run-peer` does not yet support client WebSocket mode
- it uses the daemon config’s compiled registry and expects that config to match the running daemon
- it is a sample peer for protocol bring-up, not a general interactive shell
- duplicate-vs-applied is most clearly visible in the emitted `audit disposition=...` line; the current response path is still echo-oriented

### `run-node`

Purpose:

- Starts a real listening node from a config file
- Uses the same listener/runtime shell as `run-daemon`
- Optionally initiates one outbound protocol session to another node at startup
- Lets you run two terminals and actually test node-to-node communication

Mental model:

- `run-daemon` = listener only
- `run-peer` = initiator only
- `run-node` = listener first, initiator optionally

This is the command to use when you want two processes that are both nodes.

#### Simplest two-node setup

Node A:

```bash
cd vanta-rs
cargo run -p vanta-cli -- run-node --config examples/node-a.toml
```

Node B connects to Node A and sends a request:

```bash
cd vanta-rs
cargo run -p vanta-cli -- run-node \
  --config examples/node-b.toml \
  --connect-tcp 127.0.0.1:18401 \
  --action request \
  --payload ping-from-node-b
```

What happens:

- Node A starts listeners and waits for inbound sessions
- Node B starts its own listeners
- Node B then dials Node A over TCP
- the live handshake completes
- Node B sends the request payload
- Node A responds with the current echo-style request handler

#### Command / audit flow between two nodes

Node A:

```bash
cargo run -p vanta-cli -- run-node --config examples/node-a.toml
```

Node B:

```bash
cargo run -p vanta-cli -- run-node \
  --config examples/node-b.toml \
  --connect-tcp 127.0.0.1:18401 \
  --action command \
  --payload apply-demo
```

Expected Node B output shape:

```text
node_peer_id=...
listening_tcp=127.0.0.1:18411
listening_websocket=127.0.0.1:18412
listening_unix=/tmp/vanta-node-b.sock
outbound_connect_target=127.0.0.1:18401
heartbeat ping_id=1048576 timestamp_millis=...
session_active schema_token=1098448329 capability_token=841132702
sent_Command message_id=50505050505050505050505050505050
audit disposition=Applied receipt_id=...
response disposition=Applied payload=apply-demo
outbound_session_id=...
```

#### Test duplicate command handling between nodes

Run Node A once:

```bash
cargo run -p vanta-cli -- run-node --config examples/node-a.toml
```

Then run Node B once and send the same command twice on its outbound session:

```bash
cargo run -p vanta-cli -- run-node \
  --config examples/node-b.toml \
  --connect-tcp 127.0.0.1:18401 \
  --action command \
  --payload apply-demo \
  --operation-id-hex 22222222222222222222222222222222 \
  --repeat 2
```

Expected result:

- first command: `audit disposition=Applied`
- second command in the same node process: `audit disposition=DuplicateApplied`

Why it works:

- Node B uses the fixed identity from `examples/node-b.toml`
- the command uses the same `OperationID`
- Node A persists dedup state in its SQLite backend

Important:

- `run-node` keeps running as a listener after it sends its outbound traffic
- if you try to start a second process with the same node config while the first is still alive, the listener ports will conflict

#### What `run-node` can do today

- listen on TCP, WebSocket, and Unix socket according to its config
- initiate one outbound TCP or Unix socket session at startup
- complete the handshake with another live node
- send one or more `REQUEST` or `COMMAND` messages on that outbound session
- keep running as a listener after the outbound session finishes

#### What `run-node` cannot do yet

- initiate a WebSocket client connection
- maintain multiple outbound peers or a peer table
- relay traffic between other nodes
- provide an interactive shell for sending arbitrary follow-up messages after startup
- act as a full application node with custom handlers beyond the current echo/request and audit/command behavior

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

### Generate a valid local receipt first

```bash
cargo run -p vanta-cli -- generate-audit --output receipt.bin
cargo run -p vanta-cli -- verify-audit receipt.bin
```

### Verify a receipt that came from a live daemon run

You need the raw receipt payload bytes from an `AUDIT_RECEIPT` frame. The daemon already emits those frames for handled commands, but the CLI does not yet extract the payload automatically from a captured frame. Today the practical options are:

- capture the full `AUDIT_RECEIPT` frame in your own integration test and write just the payload bytes to `receipt.bin`
- generate a local payload with `generate-audit` when you only need a valid verification example

### Bring up a real daemon and sample peer

Terminal 1:

```bash
cd vanta-rs
cargo run -p vanta-cli -- run-daemon examples/daemon.toml
```

Terminal 2:

```bash
cd vanta-rs
cargo run -p vanta-cli -- run-peer --daemon-config examples/daemon.toml --transport tcp --action request --payload ping
```

Terminal 2, command path:

```bash
cargo run -p vanta-cli -- run-peer --daemon-config examples/daemon.toml --transport tcp --action command --payload apply-demo
```

## Current limitations

- `compile-registry` currently expects JSON input, not TOML.
- `run-daemon` expects a compiled registry embedded in the TOML config rather than a manifest path.
- `verify-audit` still expects a raw receipt payload rather than a full captured `AUDIT_RECEIPT` frame.
- `verify-audit` verifies a single receipt at a time rather than an entire chain directory.
- `run-peer` is currently a scripted sample initiator, not a general-purpose REPL or full client tool.
