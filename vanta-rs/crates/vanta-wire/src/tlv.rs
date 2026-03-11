use crate::WireError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExtensionCode {
    CorrelationId = 0x01,
    OperationId = 0x02,
    IdempotencyKey = 0x03,
    RouteToken = 0x04,
    ReplyTo = 0x05,
    TopicId = 0x06,
    ChannelId = 0x07,
    BaseVersion = 0x08,
    ProjectionToken = 0x09,
    VisibilityScope = 0x0A,
    ErrorCode = 0x0B,
    AuditRef = 0x0C,
    AckRange = 0x0D,
    CreditGrant = 0x0E,
    FragmentInfo = 0x0F,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExtensionType(u8);

impl ExtensionType {
    pub fn new(code: u8, critical: bool) -> Result<Self, WireError> {
        if code == 0 {
            return Err(WireError::InvalidExtensionType);
        }
        Ok(Self(if critical { code | 0x80 } else { code & 0x7F }))
    }

    pub fn from_raw(raw: u8) -> Result<Self, WireError> {
        if raw & 0x7F == 0 {
            return Err(WireError::InvalidExtensionType);
        }
        Ok(Self(raw))
    }

    pub fn raw(self) -> u8 {
        self.0
    }

    pub fn code(self) -> u8 {
        self.0 & 0x7F
    }

    pub fn critical(self) -> bool {
        self.0 & 0x80 != 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub ty: ExtensionType,
    pub value: Bytes,
}

impl Extension {
    pub fn new(ty: ExtensionType, value: Bytes) -> Result<Self, WireError> {
        if value.len() > u8::MAX as usize {
            return Err(WireError::FieldTooLong);
        }
        Ok(Self { ty, value })
    }

    pub fn encoded_len(&self) -> usize {
        2 + self.value.len()
    }

    pub fn encode_to(&self, buf: &mut BytesMut) {
        buf.put_u8(self.ty.raw());
        buf.put_u8(self.value.len() as u8);
        buf.extend_from_slice(&self.value);
    }

    pub fn decode_many(mut buf: &[u8]) -> Result<Vec<Self>, WireError> {
        let mut out = Vec::new();
        while !buf.is_empty() {
            if buf.remaining() < 2 {
                return Err(WireError::BufferUnderflow);
            }
            let ty = ExtensionType::from_raw(buf.get_u8())?;
            let len = buf.get_u8() as usize;
            if buf.remaining() < len {
                return Err(WireError::BufferUnderflow);
            }
            let value = Bytes::copy_from_slice(&buf[..len]);
            buf.advance(len);
            let code = ty.code();
            if !matches!(code, 0x01..=0x0F) && ty.critical() {
                return Err(WireError::UnknownCriticalExtension(ty.raw()));
            }
            out.push(Self { ty, value });
        }
        Ok(out)
    }
}
