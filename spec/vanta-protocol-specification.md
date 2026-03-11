# Vanta Protocol Specification (Draft v0)

**Title:** Vanta Protocol – Secure Verifiable Data Exchange Protocol
**Status:** Draft Specification
**Version:** 0
**Intended Use:** Open protocol specification
**Author:** Vanta Project
**Date:** 2026

---

# Abstract

Vanta is a high-performance binary protocol for secure, verifiable data exchange across heterogeneous transports.
It supports client/server, peer-to-peer, relay-routed communication, and pub/sub messaging.

The protocol emphasizes:

- minimal latency
- binary efficiency
- strong cryptographic identity
- effectively-once mutation semantics
- schema evolution
- capability negotiation
- verifiable audit chains

This document defines the initial protocol specification (Version 0).

---

# 1. Introduction

Modern distributed systems require communication protocols that combine high throughput with strong security and verifiable execution guarantees.

Vanta is designed to provide:

- fast binary transport
- authenticated secure sessions
- multiplexed communication streams
- reliable mutation semantics
- cryptographically verifiable audit trails

The protocol is transport-agnostic and can operate over:

- TCP
- WebSocket
- Unix domain sockets
- relay-based routing

This document specifies the wire format, handshake protocol, control semantics, and audit mechanisms for Vanta.

---

# 2. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### Peer

A protocol participant implementing the Vanta protocol.

### Session

A cryptographically authenticated communication channel established between two peers.

### Stream

A logical communication channel multiplexed within a session.

### Frame

A single Vanta protocol unit transmitted over the transport.

### Mutation

An operation that modifies application state.

### Audit Receipt

A cryptographically signed record describing protocol events.

---

# 3. Protocol Overview

Vanta consists of four logical layers:

VAP – Application Payload Layer
VCP – Capability and Schema Negotiation
VSP – Secure Session Protocol
VTP – Transport Framing and Multiplexing

Transport is external to the protocol.

---

# 4. Protocol Architecture

```
Application
    ↑
VAP – Application Payload Layer
    ↑
VCP – Capability and Schema Negotiation
    ↑
VSP – Secure Session Layer
    ↑
VTP – Framing and Multiplexing
    ↑
Transport (TCP / WebSocket / Unix Socket / Relay)
```

---

# 5. Core Identifiers

The protocol defines several fixed-length identifiers.

| Identifier      | Size     | Description              |
| --------------- | -------- | ------------------------ |
| PeerID          | 32 bytes | Ed25519 public key       |
| SessionID       | 16 bytes | session identifier       |
| StreamID        | 8 bytes  | multiplexed stream       |
| MessageID       | 16 bytes | unique message           |
| OperationID     | 16 bytes | mutation identifier      |
| CorrelationID   | 16 bytes | request-response linkage |
| SchemaFamilyID  | 8 bytes  | schema family            |
| SchemaVersionID | 4 bytes  | schema version           |
| AuditReceiptID  | 16 bytes | receipt identifier       |

---

# 6. Transport Requirements

The transport layer MUST provide reliable delivery.

Supported transports include:

- TCP
- WebSocket
- Unix domain sockets

Relay nodes MUST forward frames without decrypting payloads.

---

# 7. Message Framing (VTP)

All protocol communication occurs via framed messages.

Frame structure:

```
Base Header (80 bytes)
Extension Block (variable)
Payload
Optional AEAD authentication tag
```

All integers are encoded in **big-endian** format.

---

# 8. Base Header Format

The base header size is fixed at 80 bytes.

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

# 9. Frame Types

The following frame types are defined.

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

Frames MAY contain extension fields encoded as TLV.

```
Type (1 byte)
Length (1 byte)
Value
```

Extensions allow protocol evolution without breaking compatibility.

---

# 11. Secure Session Protocol (VSP)

Session establishment occurs through a cryptographically authenticated handshake.

Handshake phases:

1. HELLO exchange
2. AUTH_INIT
3. AUTH_FINISH
4. NEGOTIATE
5. CAPS_CONFIRM

---

# 12. Cryptographic Suite

The default cryptographic suite is:

| Component            | Algorithm         |
| -------------------- | ----------------- |
| Identity Signature   | Ed25519           |
| Key Exchange         | X25519            |
| Key Derivation       | HKDF-SHA256       |
| Transport Encryption | ChaCha20-Poly1305 |
| Hash                 | SHA256            |

---

# 13. Peer Identity

A peer is identified by an Ed25519 public key.

```
PeerID = Ed25519 public key
```

Trust relationships are established externally.

---

# 14. Capability Negotiation (VCP)

Peers exchange supported features during session setup.

Negotiation includes:

- schema families
- schema versions
- supported capabilities
- extension namespaces

The negotiated result is represented by capability tokens.

---

# 15. Message Semantics

Vanta supports four communication models.

### Request / Response

```
REQUEST → RESPONSE
```

### Commands

Mutating operations transmitted via COMMAND frames.

### Events

Used for pub/sub notifications.

### Streams

Large or continuous data transmission.

---

# 16. Control Frames

Control-plane frames manage protocol behavior.

Examples include:

- ACK
- NACK
- FLOW_CREDIT
- HEARTBEAT
- ERROR

Control frames SHOULD be prioritized over data frames.

---

# 17. Flow Control

Flow control is receiver-driven.

Receivers grant credits to senders.

Credits limit:

- total bytes in flight
- message counts

---

# 18. Delivery Semantics

Vanta provides **effectively-once mutation semantics**.

Mutations include:

OperationID
IdempotencyKey
MessageID

Receivers maintain deduplication caches.

---

# 19. Reconnection

Connections MAY be re-established after failure.

Unresolved mutations become:

```
UNKNOWN_AFTER_DISCONNECT
```

Applications MUST reconcile state.

---

# 20. Audit System

Vanta includes a cryptographically verifiable audit system.

Audit records:

- protocol events
- mutation results
- validation outcomes

Audit records contain only metadata and hashes.

---

# 21. Audit Receipt Format

Audit receipts are transmitted via AUDIT_RECEIPT frames.

Fields include:

- ReceiptID
- Previous receipt hash
- SessionID
- MessageID
- OperationID
- SenderPeerID
- ReceiverPeerID
- EventType
- DispositionCode
- PayloadHash
- Timestamp
- Signature

---

# 22. Audit Chain

Receipts form a tamper-evident hash chain.

```
ReceiptHash_n = SHA256(receipt || prev_hash)
```

---

# 23. Security Considerations

Implementations MUST:

- verify peer signatures during handshake
- prevent nonce reuse
- reject protocol downgrades
- validate audit signatures
- ensure secure random number generation

Compromised keys may invalidate audit guarantees.

---

# 24. Privacy Considerations

Audit records intentionally exclude payload contents.

Only hashes and metadata are recorded.

Implementations SHOULD minimize metadata exposure when operating over relay networks.

---

# 25. Implementation Notes

Reference implementations are expected for:

- Rust
- Go
- TypeScript

The Rust implementation SHOULD serve as the canonical reference.

---

# 26. Future Work

Potential future extensions include:

- compression negotiation
- QUIC transport support
- Merkle-based audit trees
- multi-signer audit receipts
- zero-knowledge audit summaries

---

# 27. References

RFC 2119 – Key words for use in RFCs
RFC 8174 – RFC2119 clarifications
RFC 5869 – HKDF
RFC 8032 – Ed25519
RFC 7748 – X25519
RFC 8439 – ChaCha20-Poly1305

---

END OF SPECIFICATION
Vanta Protocol v0
