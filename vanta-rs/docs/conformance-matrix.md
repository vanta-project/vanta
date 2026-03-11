# Vanta v0 Conformance Matrix

This matrix tracks the mapping from specification requirements to code and tests in the Rust implementation.

| Spec area    | Requirement                                     | Implementation target                 | Test target                 |
| ------------ | ----------------------------------------------- | ------------------------------------- | --------------------------- |
| Core framing | Base header is fixed at 80 bytes                | `vanta-wire::BaseHeader`              | `vanta-wire` unit tests     |
| Core framing | CRC32C must validate before payload decode      | `vanta-wire::BaseHeader::decode`      | malformed header vectors    |
| Extensions   | Unknown critical TLVs reject the frame          | `vanta-wire::Extension::decode_many`  | TLV criticality tests       |
| Handshake    | Application data is blocked before activation   | `vanta-runtime::Session`              | handshake integration tests |
| Crypto       | AEAD nonce reuse is forbidden                   | `vanta-crypto::SessionKeys`           | deterministic nonce tests   |
| Negotiation  | Capabilities cannot be used before confirmation | `vanta-runtime::Session`              | negotiation mismatch tests  |
| Reliability  | Retransmits preserve identifiers                | `vanta-runtime::Session`              | retransmission tests        |
| Audit        | Receipts are append-only and signed             | `vanta-runtime::DefaultAuditVerifier` | audit verification tests    |
