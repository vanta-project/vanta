use crate::{
    AuditReceiptId, CapabilitySetId, MessageId, OperationId, PeerId, SchemaFamilyId, SessionId,
    StreamId, WireError,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub trait BinaryCodec: Sized {
    fn encode(&self) -> Result<Bytes, WireError>;
    fn decode(bytes: &[u8]) -> Result<Self, WireError>;
}

fn put_len_prefixed_str(buf: &mut BytesMut, value: &str) -> Result<(), WireError> {
    if value.len() > u8::MAX as usize {
        return Err(WireError::FieldTooLong);
    }
    buf.put_u8(value.len() as u8);
    buf.extend_from_slice(value.as_bytes());
    Ok(())
}

fn get_len_prefixed_str(buf: &mut &[u8]) -> Result<String, WireError> {
    if buf.remaining() < 1 {
        return Err(WireError::BufferUnderflow);
    }
    let len = buf.get_u8() as usize;
    if buf.remaining() < len {
        return Err(WireError::BufferUnderflow);
    }
    let value = String::from_utf8(buf[..len].to_vec())?;
    buf.advance(len);
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WireRole {
    Initiator = 1,
    Responder = 2,
    Peer = 3,
    Relay = 4,
}

impl TryFrom<u8> for WireRole {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::Initiator,
            2 => Self::Responder,
            3 => Self::Peer,
            4 => Self::Relay,
            _ => return Err(WireError::InvalidPayloadLength(value as u32)),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportProfile {
    Tcp = 1,
    WebSocket = 2,
    UnixSocket = 3,
    Relay = 4,
}

impl TryFrom<u8> for TransportProfile {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::Tcp,
            2 => Self::WebSocket,
            3 => Self::UnixSocket,
            4 => Self::Relay,
            _ => return Err(WireError::InvalidPayloadLength(value as u32)),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloPayload {
    pub role: WireRole,
    pub supported_versions: Vec<Version>,
    pub suite_ids: Vec<u8>,
    pub max_frame_size: u32,
    pub transport_profiles: Vec<TransportProfile>,
    pub features: Vec<String>,
    pub ordering_bits: u8,
}

impl BinaryCodec for HelloPayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::new();
        buf.put_u8(self.role as u8);
        buf.put_u8(self.supported_versions.len() as u8);
        for version in &self.supported_versions {
            buf.put_u8(version.major);
            buf.put_u8(version.minor);
        }
        buf.put_u8(self.suite_ids.len() as u8);
        buf.extend_from_slice(&self.suite_ids);
        buf.put_u32(self.max_frame_size);
        buf.put_u8(self.transport_profiles.len() as u8);
        for profile in &self.transport_profiles {
            buf.put_u8(*profile as u8);
        }
        buf.put_u8(self.features.len() as u8);
        for feature in &self.features {
            put_len_prefixed_str(&mut buf, feature)?;
        }
        buf.put_u8(self.ordering_bits);
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut buf = bytes;
        let role = WireRole::try_from(buf.get_u8())?;
        let version_count = buf.get_u8() as usize;
        let mut supported_versions = Vec::with_capacity(version_count);
        for _ in 0..version_count {
            supported_versions.push(Version {
                major: buf.get_u8(),
                minor: buf.get_u8(),
            });
        }
        let suite_count = buf.get_u8() as usize;
        if buf.remaining() < suite_count {
            return Err(WireError::BufferUnderflow);
        }
        let suite_ids = buf[..suite_count].to_vec();
        buf.advance(suite_count);
        let max_frame_size = buf.get_u32();
        let transport_count = buf.get_u8() as usize;
        let mut transport_profiles = Vec::with_capacity(transport_count);
        for _ in 0..transport_count {
            transport_profiles.push(TransportProfile::try_from(buf.get_u8())?);
        }
        let feature_count = buf.get_u8() as usize;
        let mut features = Vec::with_capacity(feature_count);
        for _ in 0..feature_count {
            features.push(get_len_prefixed_str(&mut buf)?);
        }
        let ordering_bits = buf.get_u8();
        Ok(Self {
            role,
            supported_versions,
            suite_ids,
            max_frame_size,
            transport_profiles,
            features,
            ordering_bits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthInitPayload {
    pub peer_id: PeerId,
    pub ephemeral_public_key: [u8; 32],
    pub freshness_nonce: [u8; 16],
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthFinishPayload {
    pub peer_id: PeerId,
    pub ephemeral_public_key: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub signature: [u8; 64],
}

impl BinaryCodec for AuthInitPayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::with_capacity(144);
        buf.extend_from_slice(self.peer_id.as_bytes());
        buf.extend_from_slice(&self.ephemeral_public_key);
        buf.extend_from_slice(&self.freshness_nonce);
        buf.extend_from_slice(&self.signature);
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != 144 {
            return Err(WireError::InvalidPayloadLength(bytes.len() as u32));
        }
        let mut buf = bytes;
        let mut peer_id = [0; 32];
        buf.copy_to_slice(&mut peer_id);
        let mut ephemeral_public_key = [0; 32];
        buf.copy_to_slice(&mut ephemeral_public_key);
        let mut freshness_nonce = [0; 16];
        buf.copy_to_slice(&mut freshness_nonce);
        let mut signature = [0; 64];
        buf.copy_to_slice(&mut signature);
        Ok(Self {
            peer_id: PeerId::from(peer_id),
            ephemeral_public_key,
            freshness_nonce,
            signature,
        })
    }
}

impl BinaryCodec for AuthFinishPayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::with_capacity(160);
        buf.extend_from_slice(self.peer_id.as_bytes());
        buf.extend_from_slice(&self.ephemeral_public_key);
        buf.extend_from_slice(&self.transcript_hash);
        buf.extend_from_slice(&self.signature);
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != 160 {
            return Err(WireError::InvalidPayloadLength(bytes.len() as u32));
        }
        let mut buf = bytes;
        let mut peer_id = [0; 32];
        buf.copy_to_slice(&mut peer_id);
        let mut ephemeral_public_key = [0; 32];
        buf.copy_to_slice(&mut ephemeral_public_key);
        let mut transcript_hash = [0; 32];
        buf.copy_to_slice(&mut transcript_hash);
        let mut signature = [0; 64];
        buf.copy_to_slice(&mut signature);
        Ok(Self {
            peer_id: PeerId::from(peer_id),
            ephemeral_public_key,
            transcript_hash,
            signature,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaDescriptorRef {
    pub family_id: SchemaFamilyId,
    pub version_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiationPayload {
    pub schemas: Vec<SchemaDescriptorRef>,
    pub capability_sets: Vec<CapabilitySetId>,
    pub extension_namespaces: Vec<String>,
    pub ordering_bits: u8,
}

impl BinaryCodec for NegotiationPayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::new();
        buf.put_u16(self.schemas.len() as u16);
        for schema in &self.schemas {
            buf.extend_from_slice(schema.family_id.as_bytes());
            buf.put_u32(schema.version_id);
        }
        buf.put_u16(self.capability_sets.len() as u16);
        for capability in &self.capability_sets {
            buf.extend_from_slice(capability.as_bytes());
        }
        buf.put_u8(self.extension_namespaces.len() as u8);
        for namespace in &self.extension_namespaces {
            put_len_prefixed_str(&mut buf, namespace)?;
        }
        buf.put_u8(self.ordering_bits);
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut buf = bytes;
        let schema_count = buf.get_u16() as usize;
        let mut schemas = Vec::with_capacity(schema_count);
        for _ in 0..schema_count {
            let mut family_id = [0; 8];
            buf.copy_to_slice(&mut family_id);
            schemas.push(SchemaDescriptorRef {
                family_id: SchemaFamilyId::from(family_id),
                version_id: buf.get_u32(),
            });
        }
        let capability_count = buf.get_u16() as usize;
        let mut capability_sets = Vec::with_capacity(capability_count);
        for _ in 0..capability_count {
            let mut capability_id = [0; 8];
            buf.copy_to_slice(&mut capability_id);
            capability_sets.push(CapabilitySetId::from(capability_id));
        }
        let namespace_count = buf.get_u8() as usize;
        let mut extension_namespaces = Vec::with_capacity(namespace_count);
        for _ in 0..namespace_count {
            extension_namespaces.push(get_len_prefixed_str(&mut buf)?);
        }
        let ordering_bits = buf.get_u8();
        Ok(Self {
            schemas,
            capability_sets,
            extension_namespaces,
            ordering_bits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsConfirmPayload {
    pub schema_token: u32,
    pub capability_token: u32,
    pub ordering_bits: u8,
}

impl BinaryCodec for CapsConfirmPayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::with_capacity(12);
        buf.put_u32(self.schema_token);
        buf.put_u32(self.capability_token);
        buf.put_u8(self.ordering_bits);
        buf.extend_from_slice(&[0, 0, 0]);
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != 12 {
            return Err(WireError::InvalidPayloadLength(bytes.len() as u32));
        }
        let mut buf = bytes;
        Ok(Self {
            schema_token: buf.get_u32(),
            capability_token: buf.get_u32(),
            ordering_bits: buf.get_u8(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub start_seq: u64,
    pub end_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckPayload {
    pub target_stream_id: StreamId,
    pub largest_contiguous_seq: u64,
    pub ranges: Vec<Range>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NackPayload {
    pub target_stream_id: StreamId,
    pub reason_code: u16,
    pub ranges: Vec<Range>,
}

fn encode_ranges(
    target_stream_id: &StreamId,
    ranges: &[Range],
    prefix: impl FnOnce(&mut BytesMut),
) -> Bytes {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(target_stream_id.as_bytes());
    prefix(&mut buf);
    buf.put_u16(ranges.len() as u16);
    for range in ranges {
        buf.put_u64(range.start_seq);
        buf.put_u64(range.end_seq);
    }
    buf.freeze()
}

fn decode_ranges(
    bytes: &[u8],
    needs_reason: bool,
) -> Result<(StreamId, u16, Vec<Range>), WireError> {
    let mut buf = bytes;
    let mut stream_id = [0; 8];
    buf.copy_to_slice(&mut stream_id);
    let reason_code = if needs_reason { buf.get_u16() } else { 0 };
    let range_count = buf.get_u16() as usize;
    let mut ranges = Vec::with_capacity(range_count);
    for _ in 0..range_count {
        ranges.push(Range {
            start_seq: buf.get_u64(),
            end_seq: buf.get_u64(),
        });
    }
    Ok((StreamId::from(stream_id), reason_code, ranges))
}

impl BinaryCodec for AckPayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(self.target_stream_id.as_bytes());
        buf.put_u64(self.largest_contiguous_seq);
        buf.put_u16(self.ranges.len() as u16);
        for range in &self.ranges {
            buf.put_u64(range.start_seq);
            buf.put_u64(range.end_seq);
        }
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut buf = bytes;
        let mut stream_id = [0; 8];
        buf.copy_to_slice(&mut stream_id);
        let largest_contiguous_seq = buf.get_u64();
        let range_count = buf.get_u16() as usize;
        let mut ranges = Vec::with_capacity(range_count);
        for _ in 0..range_count {
            ranges.push(Range {
                start_seq: buf.get_u64(),
                end_seq: buf.get_u64(),
            });
        }
        Ok(Self {
            target_stream_id: StreamId::from(stream_id),
            largest_contiguous_seq,
            ranges,
        })
    }
}

impl BinaryCodec for NackPayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        Ok(encode_ranges(&self.target_stream_id, &self.ranges, |buf| {
            buf.put_u16(self.reason_code);
        }))
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (target_stream_id, reason_code, ranges) = decode_ranges(bytes, true)?;
        Ok(Self {
            target_stream_id,
            reason_code,
            ranges,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowCreditPayload {
    pub target_stream_id: StreamId,
    pub credit_bytes: u64,
    pub credit_messages: u32,
}

impl BinaryCodec for FlowCreditPayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::with_capacity(24);
        buf.extend_from_slice(self.target_stream_id.as_bytes());
        buf.put_u64(self.credit_bytes);
        buf.put_u32(self.credit_messages);
        buf.put_u32(0);
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != 24 {
            return Err(WireError::InvalidPayloadLength(bytes.len() as u32));
        }
        let mut buf = bytes;
        let mut stream_id = [0; 8];
        buf.copy_to_slice(&mut stream_id);
        Ok(Self {
            target_stream_id: StreamId::from(stream_id),
            credit_bytes: buf.get_u64(),
            credit_messages: buf.get_u32(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeartbeatPayload {
    pub timestamp_millis: u64,
    pub ping_id: u64,
}

impl BinaryCodec for HeartbeatPayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::with_capacity(16);
        buf.put_u64(self.timestamp_millis);
        buf.put_u64(self.ping_id);
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != 16 {
            return Err(WireError::InvalidPayloadLength(bytes.len() as u32));
        }
        let mut buf = bytes;
        Ok(Self {
            timestamp_millis: buf.get_u64(),
            ping_id: buf.get_u64(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorPayload {
    pub code: u16,
    pub fatal: bool,
    pub retryable: bool,
    pub message: String,
}

impl BinaryCodec for ErrorPayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::new();
        buf.put_u16(self.code);
        let mut flags = 0u8;
        if self.fatal {
            flags |= 1;
        }
        if self.retryable {
            flags |= 1 << 1;
        }
        buf.put_u8(flags);
        buf.put_u8(0);
        if self.message.len() > u16::MAX as usize {
            return Err(WireError::FieldTooLong);
        }
        buf.put_u16(self.message.len() as u16);
        buf.extend_from_slice(self.message.as_bytes());
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut buf = bytes;
        let code = buf.get_u16();
        let flags = buf.get_u8();
        buf.get_u8();
        let len = buf.get_u16() as usize;
        if buf.remaining() < len {
            return Err(WireError::BufferUnderflow);
        }
        let message = String::from_utf8(buf[..len].to_vec())?;
        Ok(Self {
            code,
            fatal: flags & 1 != 0,
            retryable: flags & 0b10 != 0,
            message,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaHintPayload {
    pub schema_family_id: SchemaFamilyId,
    pub schema_version_id: u32,
    pub schema_token: u32,
}

impl BinaryCodec for SchemaHintPayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::with_capacity(16);
        buf.extend_from_slice(self.schema_family_id.as_bytes());
        buf.put_u32(self.schema_version_id);
        buf.put_u32(self.schema_token);
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != 16 {
            return Err(WireError::InvalidPayloadLength(bytes.len() as u32));
        }
        let mut buf = bytes;
        let mut schema_family_id = [0; 8];
        buf.copy_to_slice(&mut schema_family_id);
        Ok(Self {
            schema_family_id: SchemaFamilyId::from(schema_family_id),
            schema_version_id: buf.get_u32(),
            schema_token: buf.get_u32(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEnvelopePayload {
    pub route_token: Bytes,
    pub next_hop_peer_id: PeerId,
    pub hop_count: u8,
}

impl BinaryCodec for RouteEnvelopePayload {
    fn encode(&self) -> Result<Bytes, WireError> {
        if self.route_token.len() > u8::MAX as usize {
            return Err(WireError::FieldTooLong);
        }
        let mut buf = BytesMut::with_capacity(34 + self.route_token.len());
        buf.put_u8(self.route_token.len() as u8);
        buf.extend_from_slice(&self.route_token);
        buf.extend_from_slice(self.next_hop_peer_id.as_bytes());
        buf.put_u8(self.hop_count);
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut buf = bytes;
        let len = buf.get_u8() as usize;
        if buf.remaining() < len + 33 {
            return Err(WireError::BufferUnderflow);
        }
        let route_token = Bytes::copy_from_slice(&buf[..len]);
        buf.advance(len);
        let mut next_hop_peer_id = [0; 32];
        buf.copy_to_slice(&mut next_hop_peer_id);
        Ok(Self {
            route_token,
            next_hop_peer_id: PeerId::from(next_hop_peer_id),
            hop_count: buf.get_u8(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FragmentInfo {
    pub fragment_id: [u8; 16],
    pub fragment_index: u32,
    pub fragment_count: u32,
    pub original_payload_len: u32,
}

impl BinaryCodec for FragmentInfo {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::with_capacity(28);
        buf.extend_from_slice(&self.fragment_id);
        buf.put_u32(self.fragment_index);
        buf.put_u32(self.fragment_count);
        buf.put_u32(self.original_payload_len);
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != 28 {
            return Err(WireError::InvalidPayloadLength(bytes.len() as u32));
        }
        let mut buf = bytes;
        let mut fragment_id = [0; 16];
        buf.copy_to_slice(&mut fragment_id);
        Ok(Self {
            fragment_id,
            fragment_index: buf.get_u32(),
            fragment_count: buf.get_u32(),
            original_payload_len: buf.get_u32(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum DispositionCode {
    Applied = 1,
    DuplicateApplied = 2,
    DuplicateRejected = 3,
    ValidationFailed = 4,
    CapabilityDenied = 5,
    UnknownAfterDisconnect = 6,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditReceipt {
    pub receipt_id: AuditReceiptId,
    pub prev_receipt_hash: [u8; 32],
    pub session_id: SessionId,
    pub stream_id: StreamId,
    pub message_id: MessageId,
    pub operation_id: OperationId,
    pub sender_peer_id: PeerId,
    pub receiver_peer_id: PeerId,
    pub event_type: u16,
    pub disposition_code: DispositionCode,
    pub payload_hash: [u8; 32],
    pub timestamp_millis: u64,
    pub sequence: u64,
    pub retransmit_count: u16,
    pub validation_code: u16,
    pub signature: [u8; 64],
}

impl BinaryCodec for AuditReceipt {
    fn encode(&self) -> Result<Bytes, WireError> {
        let mut buf = BytesMut::with_capacity(288);
        buf.extend_from_slice(self.receipt_id.as_bytes());
        buf.extend_from_slice(&self.prev_receipt_hash);
        buf.extend_from_slice(self.session_id.as_bytes());
        buf.extend_from_slice(self.stream_id.as_bytes());
        buf.extend_from_slice(self.message_id.as_bytes());
        buf.extend_from_slice(self.operation_id.as_bytes());
        buf.extend_from_slice(self.sender_peer_id.as_bytes());
        buf.extend_from_slice(self.receiver_peer_id.as_bytes());
        buf.put_u16(self.event_type);
        buf.put_u16(self.disposition_code as u16);
        buf.extend_from_slice(&self.payload_hash);
        buf.put_u64(self.timestamp_millis);
        buf.put_u64(self.sequence);
        buf.put_u16(self.retransmit_count);
        buf.put_u16(self.validation_code);
        buf.extend_from_slice(&self.signature);
        Ok(buf.freeze())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != 288 {
            return Err(WireError::InvalidPayloadLength(bytes.len() as u32));
        }
        let mut buf = bytes;
        let mut receipt_id = [0; 16];
        let mut prev_receipt_hash = [0; 32];
        let mut session_id = [0; 16];
        let mut stream_id = [0; 8];
        let mut message_id = [0; 16];
        let mut operation_id = [0; 16];
        let mut sender_peer_id = [0; 32];
        let mut receiver_peer_id = [0; 32];
        let mut payload_hash = [0; 32];
        let mut signature = [0; 64];
        buf.copy_to_slice(&mut receipt_id);
        buf.copy_to_slice(&mut prev_receipt_hash);
        buf.copy_to_slice(&mut session_id);
        buf.copy_to_slice(&mut stream_id);
        buf.copy_to_slice(&mut message_id);
        buf.copy_to_slice(&mut operation_id);
        buf.copy_to_slice(&mut sender_peer_id);
        buf.copy_to_slice(&mut receiver_peer_id);
        let event_type = buf.get_u16();
        let disposition_code = match buf.get_u16() {
            1 => DispositionCode::Applied,
            2 => DispositionCode::DuplicateApplied,
            3 => DispositionCode::DuplicateRejected,
            4 => DispositionCode::ValidationFailed,
            5 => DispositionCode::CapabilityDenied,
            _ => DispositionCode::UnknownAfterDisconnect,
        };
        buf.copy_to_slice(&mut payload_hash);
        let timestamp_millis = buf.get_u64();
        let sequence = buf.get_u64();
        let retransmit_count = buf.get_u16();
        let validation_code = buf.get_u16();
        buf.copy_to_slice(&mut signature);
        Ok(Self {
            receipt_id: AuditReceiptId::from(receipt_id),
            prev_receipt_hash,
            session_id: SessionId::from(session_id),
            stream_id: StreamId::from(stream_id),
            message_id: MessageId::from(message_id),
            operation_id: OperationId::from(operation_id),
            sender_peer_id: PeerId::from(sender_peer_id),
            receiver_peer_id: PeerId::from(receiver_peer_id),
            event_type,
            disposition_code,
            payload_hash,
            timestamp_millis,
            sequence,
            retransmit_count,
            validation_code,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let hello = HelloPayload {
            role: WireRole::Initiator,
            supported_versions: vec![Version { major: 0, minor: 0 }],
            suite_ids: vec![1],
            max_frame_size: 4096,
            transport_profiles: vec![TransportProfile::Tcp, TransportProfile::WebSocket],
            features: vec!["resume".into(), "audit".into()],
            ordering_bits: 0b111,
        };
        let encoded = hello.encode().expect("encode");
        let decoded = HelloPayload::decode(&encoded).expect("decode");
        assert_eq!(decoded.features, hello.features);
        assert_eq!(decoded.transport_profiles, hello.transport_profiles);
    }
}
