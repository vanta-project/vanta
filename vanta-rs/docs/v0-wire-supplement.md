# Vanta v0 Wire Supplement

This document closes the v0 gaps that were left implicit in the prose specification and is the normative companion for the Rust reference implementation.

## Frame lengths

- `HeaderLength` is `80 + ExtensionLength`.
- `FrameLength` is `HeaderLength + PayloadLength + optional_aead_tag_len`.
- AEAD trailers are exactly 16 bytes when the `ENC` flag is present.

## TLV criticality

- TLV types use the high bit as a criticality marker.
- `0x00` is invalid.
- Unknown critical TLVs abort frame parsing.
- Unknown non-critical TLVs are preserved when decoding and re-encoding, but may be ignored by higher layers.

## Control and handshake payload layouts

All integer fields are big-endian.

- `HELLO`
  - `role:u8`
  - `version_count:u8`, then repeated `major:u8 minor:u8`
  - `suite_count:u8`, then repeated `suite_id:u8`
  - `max_frame_size:u32`
  - `transport_count:u8`, then repeated `transport_id:u8`
  - `feature_count:u8`, then repeated `len:u8 value:bytes`
  - `ordering_bits:u8`
- `AUTH_INIT`
  - `peer_id:32`
  - `ephemeral_public_key:32`
  - `freshness_nonce:16`
  - `signature:64`
- `AUTH_FINISH`
  - `peer_id:32`
  - `ephemeral_public_key:32`
  - `transcript_hash:32`
  - `signature:64`
- `NEGOTIATE`
  - `schema_count:u16`, repeated `family_id:u64 version_id:u32`
  - `capability_count:u16`, repeated `set_id:u64`
  - `namespace_count:u8`, repeated `len:u8 utf8-bytes`
  - `ordering_bits:u8`
- `CAPS_CONFIRM`
  - `schema_token:u32`
  - `capability_token:u32`
  - `ordering_bits:u8`
  - `reserved:3`
- `ACK`
  - `target_stream_id:u64`
  - `largest_contiguous_seq:u64`
  - `range_count:u16`
  - repeated `start_seq:u64 end_seq:u64`
- `NACK`
  - `target_stream_id:u64`
  - `reason_code:u16`
  - `range_count:u16`
  - repeated `start_seq:u64 end_seq:u64`
- `FLOW_CREDIT`
  - `target_stream_id:u64`
  - `credit_bytes:u64`
  - `credit_messages:u32`
  - `reserved:u32`
- `HEARTBEAT`
  - `timestamp_millis:u64`
  - `ping_id:u64`
- `ERROR`
  - `code:u16`
  - `flags:u8` bit0=`fatal`, bit1=`retryable`
  - `reserved:u8`
  - `message_len:u16`
  - `message_bytes`
- `SCHEMA_HINT`
  - `schema_family_id:u64`
  - `schema_version_id:u32`
  - `schema_token:u32`
- `ROUTE_ENVELOPE`
  - `route_token_len:u8`
  - `route_token:bytes`
  - `next_hop_peer_id:32`
  - `hop_count:u8`
- `FragmentInfo` TLV value
  - `fragment_id:16`
  - `fragment_index:u32`
  - `fragment_count:u32`
  - `original_payload_len:u32`

## Key schedule

HKDF labels are fixed ASCII values:

- `vanta/c2s/key`
- `vanta/s2c/key`
- `vanta/c2s/nonce`
- `vanta/s2c/nonce`
- `vanta/resume`
- `vanta/audit`
- `vanta/session-id`

## Registry tokens

- `SchemaToken` is computed over the canonical schema descriptor set.
- `CapabilityToken` is computed over the canonical capability descriptor set.
- Token collisions are fatal during registry compilation.
