use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! id_type {
    ($name:ident, $len:expr) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Default,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Serialize,
            Deserialize,
        )]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(value: [u8; $len]) -> Self {
                Self(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }
    };
}

id_type!(PeerId, 32);
id_type!(SessionId, 16);
id_type!(StreamId, 8);
id_type!(MessageId, 16);
id_type!(OperationId, 16);
id_type!(CorrelationId, 16);
id_type!(AuditReceiptId, 16);
id_type!(SchemaFamilyId, 8);
id_type!(CapabilitySetId, 8);
