use crate::{Extension, WireError};
use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const MAGIC: [u8; 4] = *b"VTP1";
pub const BASE_HEADER_LEN: usize = 80;
pub const MAX_EXTENSION_LENGTH: usize = u16::MAX as usize;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FrameFlags: u8 {
        const ENC = 0b0000_0001;
        const E2E = 0b0000_0010;
        const ACK_REQ = 0b0000_0100;
        const ORDERED = 0b0000_1000;
        const CTRL = 0b0001_0000;
        const RETRANSMIT = 0b0010_0000;
        const FRAG = 0b0100_0000;
        const RESERVED = 0b1000_0000;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 0x01,
    Auth = 0x02,
    Negotiate = 0x03,
    Caps = 0x04,
    Request = 0x10,
    Response = 0x11,
    Command = 0x12,
    Event = 0x13,
    StreamOpen = 0x20,
    StreamData = 0x21,
    StreamClose = 0x22,
    Ack = 0x30,
    Nack = 0x31,
    FlowCredit = 0x32,
    Heartbeat = 0x33,
    Error = 0x34,
    AuditReceipt = 0x35,
    SchemaHint = 0x36,
    RouteEnvelope = 0x37,
}

impl TryFrom<u8> for FrameType {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, WireError> {
        Ok(match value {
            0x01 => Self::Hello,
            0x02 => Self::Auth,
            0x03 => Self::Negotiate,
            0x04 => Self::Caps,
            0x10 => Self::Request,
            0x11 => Self::Response,
            0x12 => Self::Command,
            0x13 => Self::Event,
            0x20 => Self::StreamOpen,
            0x21 => Self::StreamData,
            0x22 => Self::StreamClose,
            0x30 => Self::Ack,
            0x31 => Self::Nack,
            0x32 => Self::FlowCredit,
            0x33 => Self::Heartbeat,
            0x34 => Self::Error,
            0x35 => Self::AuditReceipt,
            0x36 => Self::SchemaHint,
            0x37 => Self::RouteEnvelope,
            other => return Err(WireError::UnsupportedFrameType(other)),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseHeader {
    pub major_version: u8,
    pub minor_version: u8,
    pub header_length: u16,
    pub frame_length: u32,
    pub extension_length: u16,
    pub frame_type: FrameType,
    pub flags: FrameFlags,
    pub header_crc32c: u32,
    pub session_id: [u8; 16],
    pub stream_id: [u8; 8],
    pub message_id: [u8; 16],
    pub sequence: u64,
    pub payload_length: u32,
    pub schema_token: u32,
    pub capability_token: u32,
}

impl BaseHeader {
    pub fn new(frame_type: FrameType, flags: FrameFlags, payload_length: usize) -> Self {
        Self {
            major_version: 0,
            minor_version: 0,
            header_length: BASE_HEADER_LEN as u16,
            frame_length: (BASE_HEADER_LEN + payload_length) as u32,
            extension_length: 0,
            frame_type,
            flags,
            header_crc32c: 0,
            session_id: [0; 16],
            stream_id: [0; 8],
            message_id: [0; 16],
            sequence: 0,
            payload_length: payload_length as u32,
            schema_token: 0,
            capability_token: 0,
        }
    }

    pub fn with_extension_length(mut self, extension_length: usize) -> Result<Self, WireError> {
        if extension_length > MAX_EXTENSION_LENGTH {
            return Err(WireError::InvalidExtensionLength(extension_length as u16));
        }
        self.extension_length = extension_length as u16;
        self.header_length = (BASE_HEADER_LEN + extension_length) as u16;
        self.frame_length = self.header_length as u32 + self.payload_length;
        Ok(self)
    }

    pub fn has_aead_tag(&self) -> bool {
        self.flags.contains(FrameFlags::ENC)
    }

    pub fn compute_crc32c(&self) -> u32 {
        let mut buf = self.encode_base_header(0);
        crc32c::crc32c(&buf.split().freeze())
    }

    pub fn validate(&self) -> Result<(), WireError> {
        if self.flags.contains(FrameFlags::RESERVED) {
            return Err(WireError::ReservedFlag);
        }
        if self.header_length as usize != BASE_HEADER_LEN + self.extension_length as usize {
            return Err(WireError::InvalidHeaderLength(self.header_length));
        }
        let tag_len = if self.has_aead_tag() { 16 } else { 0 };
        let expected = self.header_length as u32 + self.payload_length + tag_len;
        if self.frame_length != expected {
            return Err(WireError::InvalidFrameLength(self.frame_length));
        }
        if self.extension_length as usize > MAX_EXTENSION_LENGTH {
            return Err(WireError::InvalidExtensionLength(self.extension_length));
        }
        Ok(())
    }

    pub fn encode_base_header(&self, crc_override: u32) -> BytesMut {
        let mut buf = BytesMut::with_capacity(BASE_HEADER_LEN);
        buf.extend_from_slice(&MAGIC);
        buf.put_u8(self.major_version);
        buf.put_u8(self.minor_version);
        buf.put_u16(self.header_length);
        buf.put_u32(self.frame_length);
        buf.put_u16(self.extension_length);
        buf.put_u8(self.frame_type as u8);
        buf.put_u8(self.flags.bits());
        buf.put_u32(crc_override);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.stream_id);
        buf.extend_from_slice(&self.message_id);
        buf.put_u64(self.sequence);
        buf.put_u32(self.payload_length);
        buf.put_u32(self.schema_token);
        buf.put_u32(self.capability_token);
        buf
    }

    pub fn encode_to(&self, buf: &mut BytesMut) {
        let crc = self.compute_crc32c();
        let encoded = self.encode_base_header(crc);
        buf.extend_from_slice(&encoded);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < BASE_HEADER_LEN {
            return Err(WireError::BufferUnderflow);
        }
        if buf[..4] != MAGIC {
            return Err(WireError::InvalidMagic);
        }
        let mut cursor = &buf[..BASE_HEADER_LEN];
        cursor.advance(4);
        let major_version = cursor.get_u8();
        let minor_version = cursor.get_u8();
        let header_length = cursor.get_u16();
        let frame_length = cursor.get_u32();
        let extension_length = cursor.get_u16();
        let frame_type = FrameType::try_from(cursor.get_u8())?;
        let flags = FrameFlags::from_bits_retain(cursor.get_u8());
        let header_crc32c = cursor.get_u32();
        let mut session_id = [0; 16];
        cursor.copy_to_slice(&mut session_id);
        let mut stream_id = [0; 8];
        cursor.copy_to_slice(&mut stream_id);
        let mut message_id = [0; 16];
        cursor.copy_to_slice(&mut message_id);
        let sequence = cursor.get_u64();
        let payload_length = cursor.get_u32();
        let schema_token = cursor.get_u32();
        let capability_token = cursor.get_u32();

        let header = Self {
            major_version,
            minor_version,
            header_length,
            frame_length,
            extension_length,
            frame_type,
            flags,
            header_crc32c,
            session_id,
            stream_id,
            message_id,
            sequence,
            payload_length,
            schema_token,
            capability_token,
        };
        header.validate()?;
        if header.compute_crc32c() != header.header_crc32c {
            return Err(WireError::InvalidCrc32c);
        }
        Ok(header)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub header: BaseHeader,
    pub extensions: Vec<Extension>,
    pub payload: Bytes,
    pub aead_tag: Option<[u8; 16]>,
}

impl Frame {
    pub fn new(frame_type: FrameType, flags: FrameFlags, payload: Bytes) -> Self {
        let header = BaseHeader::new(frame_type, flags, payload.len());
        Self {
            header,
            extensions: Vec::new(),
            payload,
            aead_tag: None,
        }
    }

    pub fn with_extensions(mut self, extensions: Vec<Extension>) -> Result<Self, WireError> {
        let extension_length = extensions.iter().map(Extension::encoded_len).sum();
        self.header = self
            .header
            .clone()
            .with_extension_length(extension_length)?;
        self.extensions = extensions;
        self.refresh_lengths()?;
        Ok(self)
    }

    pub fn with_aead_tag(mut self, tag: [u8; 16]) -> Result<Self, WireError> {
        self.header.flags.insert(FrameFlags::ENC);
        self.aead_tag = Some(tag);
        self.refresh_lengths()?;
        Ok(self)
    }

    pub fn refresh_lengths(&mut self) -> Result<(), WireError> {
        let extension_length: usize = self.extensions.iter().map(Extension::encoded_len).sum();
        self.header.extension_length = extension_length as u16;
        self.header.header_length = (BASE_HEADER_LEN + extension_length) as u16;
        self.header.payload_length = self.payload.len() as u32;
        self.header.frame_length = self.header.header_length as u32
            + self.header.payload_length
            + u32::from(self.aead_tag.is_some()) * 16;
        self.header.validate()
    }

    pub fn encode(&self) -> Result<Bytes, WireError> {
        self.header.validate()?;
        let mut buf = BytesMut::with_capacity(self.header.frame_length as usize);
        self.header.encode_to(&mut buf);
        for extension in &self.extensions {
            extension.encode_to(&mut buf);
        }
        buf.extend_from_slice(&self.payload);
        if let Some(tag) = self.aead_tag {
            buf.extend_from_slice(&tag);
        }
        Ok(buf.freeze())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let header = BaseHeader::decode(buf)?;
        if buf.len() < header.frame_length as usize {
            return Err(WireError::BufferUnderflow);
        }
        let extension_start = BASE_HEADER_LEN;
        let extension_end = extension_start + header.extension_length as usize;
        let payload_end = extension_end + header.payload_length as usize;
        let extensions = Extension::decode_many(&buf[extension_start..extension_end])?;
        let payload = Bytes::copy_from_slice(&buf[extension_end..payload_end]);
        let aead_tag = if header.has_aead_tag() {
            let mut tag = [0; 16];
            tag.copy_from_slice(&buf[payload_end..payload_end + 16]);
            Some(tag)
        } else {
            None
        };
        Ok(Self {
            header,
            extensions,
            payload,
            aead_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExtensionCode, ExtensionType};

    #[test]
    fn crc_roundtrip() {
        let extension = Extension::new(
            ExtensionType::new(ExtensionCode::CorrelationId as u8, false).expect("extension type"),
            Bytes::from_static(&[1, 2, 3, 4]),
        )
        .expect("extension");
        let frame = Frame::new(
            FrameType::Request,
            FrameFlags::ACK_REQ,
            Bytes::from_static(b"hello"),
        )
        .with_extensions(vec![extension])
        .expect("frame");
        let encoded = frame.encode().expect("encode");
        let decoded = Frame::decode(&encoded).expect("decode");
        assert_eq!(decoded.payload, Bytes::from_static(b"hello"));
        assert_eq!(decoded.extensions.len(), 1);
    }
}
