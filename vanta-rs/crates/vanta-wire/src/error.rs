use thiserror::Error;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("buffer underflow while decoding")]
    BufferUnderflow,
    #[error("invalid magic")]
    InvalidMagic,
    #[error("unsupported frame type {0:#x}")]
    UnsupportedFrameType(u8),
    #[error("reserved flag bit set")]
    ReservedFlag,
    #[error("invalid header length {0}")]
    InvalidHeaderLength(u16),
    #[error("invalid extension length {0}")]
    InvalidExtensionLength(u16),
    #[error("invalid frame length {0}")]
    InvalidFrameLength(u32),
    #[error("invalid payload length {0}")]
    InvalidPayloadLength(u32),
    #[error("invalid crc32c")]
    InvalidCrc32c,
    #[error("invalid extension type 0")]
    InvalidExtensionType,
    #[error("unknown critical extension type {0:#x}")]
    UnknownCriticalExtension(u8),
    #[error("field too long for compact encoding")]
    FieldTooLong,
    #[error("utf-8 error")]
    Utf8(#[from] std::string::FromUtf8Error),
}
