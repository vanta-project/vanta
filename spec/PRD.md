# VANTA TRANSPORT PROTOCOL

Product Requirements & Technical Specification
Version: v0
Status: Draft

# 1. Overview

**Vanta** is a high-performance binary protocol for secure, verifiable data exchange across heterogeneous transports.

It is designed for systems requiring:

- extremely fast message exchange
- minimal wire overhead
- strong cryptographic identity
- verifiable execution history
- flexible interaction models
- transport independence

Supported interaction patterns:

- client/server
- peer-to-peer
- pub/sub
- relay-routed peer communication
- streaming

Supported transports:

- TCP
- WebSocket
- Unix domain sockets
- relay forwarding channels

---

# 2. Design Goals

The protocol prioritizes:

### Performance

- binary-only encoding
- fixed-offset header fields
- zero-copy payload handling
- multiplexed streams

### Security

- mutual peer authentication
- forward secrecy
- encrypted transport
- optional end-to-end payload encryption
- MITM resistance

### Reliability

- effectively-once mutation semantics
- explicit failure reporting
- controlled retransmission
- receiver-driven flow control

### Extensibility

- schema negotiation
- capability negotiation
- extension namespaces
- forward-compatible wire format

### Auditability

- cryptographically signed receipts
- tamper-evident receipt chain
- minimal data exposure

---

# 3. Protocol Layer Model

```text
Application
    ↑
VAP – Application Payload Layer
    ↑
VCP – Capability + Schema Negotiation
    ↑
VSP – Secure Session Layer
    ↑
VTP – Framing + Multiplexing Layer
    ↑
Transport (TCP / WebSocket / Unix Socket / Relay)
```

---

# 4. Core Identifiers

| Identifier      | Size     | Purpose               |
| --------------- | -------- | --------------------- |
| PeerID          | 32 bytes | Ed25519 public key    |
| SessionID       | 16 bytes | session identifier    |
| StreamID        | 8 bytes  | multiplexed stream    |
| MessageID       | 16 bytes | unique message        |
| OperationID     | 16 bytes | mutation identifier   |
| CorrelationID   | 16 bytes | request-response link |
| SchemaFamilyID  | 8 bytes  | schema family         |
| SchemaVersionID | 4 bytes  | schema version        |
| CapabilitySetID | 8 bytes  | capability group      |
| AuditReceiptID  | 16 bytes | audit identifier      |

---

# 5. Transport Requirements

Transport must provide:

- reliable delivery
- ordered byte stream or message boundary support

Supported transports:

- TCP
- WebSocket
- Unix sockets
- relay routing

Relay nodes must:

- forward frames
- not decrypt encrypted payload
- not modify frame content

---

# 6. Wire Format (VTP)

Every frame consists of:

```text
Base Header (80 bytes)
Extension Block (variable)
Payload (variable)
AEAD Tag (optional, 16 bytes)
```

All integers are **big-endian**.

---

# 7. Base Header Layout (80 bytes)

| Offset | Size | Field           |
| ------ | ---- | --------------- |
| 0      | 4    | Magic (`VTP1`)  |
| 4      | 1    | MajorVersion    |
| 5      | 1    | MinorVersion    |
| 6      | 2    | HeaderLength    |
| 8      | 4    | FrameLength     |
| 12     | 2    | ExtensionLength |
| 14     | 1    | FrameType       |
| 15     | 1    | Flags           |
| 16     | 4    | HeaderCRC32C    |
| 20     | 16   | SessionID       |
| 36     | 8    | StreamID        |
| 44     | 16   | MessageID       |
| 60     | 8    | Sequence        |
| 68     | 4    | PayloadLength   |
| 72     | 4    | SchemaToken     |
| 76     | 4    | CapabilityToken |

---

# 8. Frame Flags

| Bit | Name       | Meaning                      |
| --- | ---------- | ---------------------------- |
| 0   | ENC        | encrypted session frame      |
| 1   | E2E        | end-to-end encrypted payload |
| 2   | ACK_REQ    | explicit ack required        |
| 3   | ORDERED    | ordered stream               |
| 4   | CTRL       | control-plane frame          |
| 5   | RETRANSMIT | retransmission               |
| 6   | FRAG       | fragmented payload           |
| 7   | RESERVED   | unused                       |

---

# 9. Frame Types

| Code | Name           |
| ---- | -------------- |
| 0x01 | HELLO          |
| 0x02 | AUTH           |
| 0x03 | NEGOTIATE      |
| 0x04 | CAPS           |
| 0x10 | REQUEST        |
| 0x11 | RESPONSE       |
| 0x12 | COMMAND        |
| 0x13 | EVENT          |
| 0x20 | STREAM_OPEN    |
| 0x21 | STREAM_DATA    |
| 0x22 | STREAM_CLOSE   |
| 0x30 | ACK            |
| 0x31 | NACK           |
| 0x32 | FLOW_CREDIT    |
| 0x33 | HEARTBEAT      |
| 0x34 | ERROR          |
| 0x35 | AUDIT_RECEIPT  |
| 0x36 | SCHEMA_HINT    |
| 0x37 | ROUTE_ENVELOPE |

---

# 10. Extension Block

Extension blocks use **TLV encoding**:

```text
Type (1 byte)
Length (1 byte)
Value (variable)
```

Core TLV extensions:

| Type | Meaning         |
| ---- | --------------- |
| 0x01 | CorrelationID   |
| 0x02 | OperationID     |
| 0x03 | IdempotencyKey  |
| 0x04 | RouteToken      |
| 0x05 | ReplyTo         |
| 0x06 | TopicID         |
| 0x07 | ChannelID       |
| 0x08 | BaseVersion     |
| 0x09 | ProjectionToken |
| 0x0A | VisibilityScope |
| 0x0B | ErrorCode       |
| 0x0C | AuditRef        |
| 0x0D | AckRange        |
| 0x0E | CreditGrant     |
| 0x0F | FragmentInfo    |

---

# 11. Secure Session (VSP)

Session handshake phases:

1. HELLO exchange
2. AUTH_INIT
3. AUTH_FINISH
4. NEGOTIATE
5. CAPS_CONFIRM

---

# 12. Cryptographic Suite

Default suite:

| Component            | Algorithm         |
| -------------------- | ----------------- |
| Identity signature   | Ed25519           |
| Key exchange         | X25519            |
| KDF                  | HKDF-SHA256       |
| Transport encryption | ChaCha20-Poly1305 |
| Hash                 | SHA256            |

---

# 13. Peer Identity

Peer identity:

```text
PeerID = Ed25519 public key
```

Trust established via:

- pinned keys
- registry-based trust
- application-level trust

Certificates are not required in v0.

---

# 14. Session Key Derivation

Ephemeral exchange:

```text
dh_secret = X25519(local_private, remote_public)
```

Session secret:

```text
handshake_secret = HKDF(dh_secret)
```

Derived keys:

- client→server key
- server→client key
- nonce bases
- resume secret
- audit binding key

SessionID derived from transcript hash.

---

# 15. Capability Negotiation

Peers exchange:

- supported capabilities
- supported schema families
- supported schema versions
- extension namespaces

Final negotiated set represented by:

```text
CapabilityToken
SchemaToken
```

---

# 16. Message Semantics

Vanta supports four interaction models.

### Request / Response

```text
REQUEST → RESPONSE
```

### Commands (mutations)

```text
COMMAND
```

Must include:

- OperationID
- IdempotencyKey

### Events

```text
EVENT
```

Used for pub/sub.

### Streams

```text
STREAM_OPEN
STREAM_DATA
STREAM_CLOSE
```

---

# 17. Delivery Semantics

Vanta implements **effectively-once mutation semantics**.

Receiver maintains a dedup cache keyed by:

```text
PeerID + OperationID
```

Possible outcomes:

| Result             |
| ------------------ |
| APPLIED            |
| DUPLICATE_APPLIED  |
| DUPLICATE_REJECTED |
| VALIDATION_FAILED  |
| CAPABILITY_DENIED  |

---

# 18. Control Plane

Control frames manage protocol behavior.

Control-plane messages:

- ACK
- NACK
- FLOW_CREDIT
- HEARTBEAT
- ERROR
- AUDIT_RECEIPT

Control plane is prioritized over data plane.

---

# 19. Acknowledgements

### Transport ACK

Confirms frame received and parsed.

### Semantic ACK

Confirms mutation or request result.

Returned via:

- RESPONSE
- AUDIT_RECEIPT

---

# 20. ACK Frame

Payload:

```text
TargetStreamID (8)
LargestContiguousSeq (8)
RangeCount (2)
AckRanges
```

Ack range:

```text
StartSeq (8)
EndSeq (8)
```

---

# 21. Flow Control

Receiver grants credits.

FLOW_CREDIT payload:

```text
TargetStreamID (8)
CreditBytes (8)
CreditMessages (4)
```

Sender must stop sending when credits exhausted.

---

# 22. Retransmission

Retransmitted frames:

- preserve MessageID
- preserve Sequence
- set RETRANSMIT flag

Retransmission typically triggered by:

```text
NACK
```

---

# 23. Heartbeat

Heartbeat payload:

```text
Timestamp (8)
PingID (8)
```

Used for:

- RTT measurement
- idle detection
- connection health

---

# 24. Error Model

Errors transmitted via:

```text
ERROR
```

Example codes:

| Code | Meaning                |
| ---- | ---------------------- |
| 2001 | VERSION_UNSUPPORTED    |
| 2005 | AUTH_SIGNATURE_INVALID |
| 3001 | SCHEMA_UNSUPPORTED     |
| 4001 | CAPABILITY_REQUIRED    |
| 6001 | FLOW_WINDOW_EXCEEDED   |

---

# 25. Stream Lifecycle

```text
STREAM_OPEN
STREAM_DATA
STREAM_CLOSE
```

Stream ordering modes:

| Mode        |
| ----------- |
| UNORDERED   |
| ORDERED     |
| KEY_ORDERED |

---

# 26. Fragmentation

Large payloads may be fragmented.

Fragment metadata:

```text
FragmentID
FragmentIndex
FragmentCount
```

Receiver reassembles before delivery.

---

# 27. Reconnection

Reconnect behavior:

- exponential backoff
- peer identity preserved
- message IDs preserved

Unresolved mutations become:

```text
UNKNOWN_AFTER_DISCONNECT
```

Clients must reconcile using application logic.

---

# 28. Audit System Overview

Vanta includes a **cryptographically verifiable audit system**.

Audit provides:

- tamper detection
- operation accountability
- execution proof

Audit records contain:

- metadata
- payload hash
- signature

Payload contents are never included.

---

# 29. Audit Chain

Receipts form an append-only hash chain.

```
ReceiptHash_n = SHA256(receipt || prev_hash)
```

Ensures tamper detection.

---

# 30. AUDIT_RECEIPT Frame

Payload structure:

```text
ReceiptID (16)
PrevReceiptHash (32)
SessionID (16)
StreamID (8)
MessageID (16)
OperationID (16)
SenderPeerID (32)
ReceiverPeerID (32)
EventType (2)
DispositionCode (2)
PayloadHash (32)
Timestamp (8)
Sequence (8)
RetransmitCount (2)
ValidationCode (2)
Signature (64)
```

---

# 31. Audit Event Types

Examples:

| Event                     |
| ------------------------- |
| COMMAND_APPLIED           |
| COMMAND_REJECTED          |
| COMMAND_DUPLICATE_APPLIED |
| SCHEMA_VIOLATION          |
| CAPABILITY_DENIED         |
| RETRANSMISSION            |
| SESSION_ESTABLISHED       |

---

# 32. Receipt Signature

Receipts signed using:

```text
Ed25519
```

Signature covers:

```text
SHA256(canonical_receipt_fields)
```

---

# 33. Audit Verification

Verification steps:

1. verify signature
2. recompute receipt hash
3. verify chain continuity
4. verify payload hash
5. verify referenced message

---

# 34. Privacy Properties

Audit records contain only:

- hashes
- identifiers
- metadata

They do **not** contain:

- payload data
- queries
- application state

---

# 35. Protocol Invariants

1. every message has unique MessageID
2. every mutation has OperationID
3. no capability used before negotiation
4. unknown schema fields ignored
5. no silent downgrade allowed
6. audit chain must not fork
7. session encryption mandatory
8. retransmissions preserve identifiers

---

# 36. Reference Implementation Targets

Initial implementations:

- Rust (reference)
- Go (service environments)
- TypeScript (browser)

Suggested repositories:

```text
vanta-rs
vanta-go
vanta-ts
```

---

# 37. Future Extensions

Planned areas:

- compression negotiation
- Merkle audit trees
- multi-signer receipts
- hardware-backed signatures
- zero-knowledge audit summaries
- QUIC transport support

---

END OF SPECIFICATION
VANTA PROTOCOL v0
