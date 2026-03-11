use async_trait::async_trait;
use bytes::Bytes;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use vanta_registry::CompiledRegistry;
use vanta_wire::{AuditReceipt, BinaryCodec, MessageId, OperationId, PeerId, SessionId};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sqlite error")]
    Sql(#[from] rusqlite::Error),
    #[error("serialization error")]
    Serde(#[from] serde_json::Error),
    #[error("wire error")]
    Wire(#[from] vanta_wire::WireError),
    #[error("lock poisoned")]
    LockPoisoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedupRecord {
    pub peer_id: PeerId,
    pub operation_id: OperationId,
    pub message_id: MessageId,
    pub disposition_code: u16,
    pub timestamp_millis: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeRecord {
    pub ticket_id: [u8; 16],
    pub session_id: SessionId,
    pub peer_id: PeerId,
    pub resume_secret: [u8; 32],
    pub last_sequence: u64,
    pub expires_at_millis: u64,
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn get_dedup(
        &self,
        peer_id: PeerId,
        operation_id: OperationId,
    ) -> Result<Option<DedupRecord>, StorageError>;
    async fn put_dedup(&self, record: DedupRecord) -> Result<(), StorageError>;
    async fn get_resume(&self, ticket_id: [u8; 16]) -> Result<Option<ResumeRecord>, StorageError>;
    async fn put_resume(&self, record: ResumeRecord) -> Result<(), StorageError>;
    async fn latest_audit_hash(&self) -> Result<Option<[u8; 32]>, StorageError>;
    async fn append_audit(
        &self,
        receipt: &AuditReceipt,
        receipt_hash: [u8; 32],
    ) -> Result<(), StorageError>;
    async fn cache_registry(&self, registry: &CompiledRegistry) -> Result<(), StorageError>;
    async fn load_registry(&self) -> Result<Option<CompiledRegistry>, StorageError>;
}

#[derive(Clone, Default)]
pub struct MemoryStorage {
    dedup: Arc<Mutex<Vec<DedupRecord>>>,
    resumes: Arc<Mutex<Vec<ResumeRecord>>>,
    audits: Arc<Mutex<Vec<([u8; 32], Bytes)>>>,
    registry: Arc<Mutex<Option<CompiledRegistry>>>,
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn get_dedup(
        &self,
        peer_id: PeerId,
        operation_id: OperationId,
    ) -> Result<Option<DedupRecord>, StorageError> {
        let records = self.dedup.lock().map_err(|_| StorageError::LockPoisoned)?;
        Ok(records
            .iter()
            .find(|record| record.peer_id == peer_id && record.operation_id == operation_id)
            .cloned())
    }

    async fn put_dedup(&self, record: DedupRecord) -> Result<(), StorageError> {
        self.dedup
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?
            .push(record);
        Ok(())
    }

    async fn get_resume(&self, ticket_id: [u8; 16]) -> Result<Option<ResumeRecord>, StorageError> {
        let records = self
            .resumes
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?;
        Ok(records
            .iter()
            .find(|record| record.ticket_id == ticket_id)
            .cloned())
    }

    async fn put_resume(&self, record: ResumeRecord) -> Result<(), StorageError> {
        self.resumes
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?
            .push(record);
        Ok(())
    }

    async fn latest_audit_hash(&self) -> Result<Option<[u8; 32]>, StorageError> {
        let audits = self.audits.lock().map_err(|_| StorageError::LockPoisoned)?;
        Ok(audits.last().map(|(hash, _)| *hash))
    }

    async fn append_audit(
        &self,
        receipt: &AuditReceipt,
        receipt_hash: [u8; 32],
    ) -> Result<(), StorageError> {
        let encoded = receipt.encode()?;
        self.audits
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?
            .push((receipt_hash, encoded));
        Ok(())
    }

    async fn cache_registry(&self, registry: &CompiledRegistry) -> Result<(), StorageError> {
        *self
            .registry
            .lock()
            .map_err(|_| StorageError::LockPoisoned)? = Some(registry.clone());
        Ok(())
    }

    async fn load_registry(&self) -> Result<Option<CompiledRegistry>, StorageError> {
        Ok(self
            .registry
            .lock()
            .map_err(|_| StorageError::LockPoisoned)?
            .clone())
    }
}

#[derive(Clone)]
pub struct SqliteStorage {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS dedup (
                peer_id BLOB NOT NULL,
                operation_id BLOB NOT NULL,
                message_id BLOB NOT NULL,
                disposition_code INTEGER NOT NULL,
                timestamp_millis INTEGER NOT NULL,
                PRIMARY KEY(peer_id, operation_id)
            );
            CREATE TABLE IF NOT EXISTS resume_state (
                ticket_id BLOB PRIMARY KEY,
                session_id BLOB NOT NULL,
                peer_id BLOB NOT NULL,
                resume_secret BLOB NOT NULL,
                last_sequence INTEGER NOT NULL,
                expires_at_millis INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_bytes BLOB NOT NULL,
                receipt_hash BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registry_cache (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                compiled_json TEXT NOT NULL
            );
            "#,
        )?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StorageError> {
        self.connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)
    }
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn get_dedup(
        &self,
        peer_id: PeerId,
        operation_id: OperationId,
    ) -> Result<Option<DedupRecord>, StorageError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT message_id, disposition_code, timestamp_millis FROM dedup WHERE peer_id = ?1 AND operation_id = ?2",
                params![peer_id.as_bytes().as_slice(), operation_id.as_bytes().as_slice()],
                |row| {
                    let message_id: Vec<u8> = row.get(0)?;
                    let disposition_code = row.get(1)?;
                    let timestamp_millis = row.get(2)?;
                    Ok(DedupRecord {
                        peer_id,
                        operation_id,
                        message_id: MessageId::from(message_id.try_into().unwrap_or([0; 16])),
                        disposition_code,
                        timestamp_millis,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    async fn put_dedup(&self, record: DedupRecord) -> Result<(), StorageError> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT OR REPLACE INTO dedup(peer_id, operation_id, message_id, disposition_code, timestamp_millis) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                record.peer_id.as_bytes().as_slice(),
                record.operation_id.as_bytes().as_slice(),
                record.message_id.as_bytes().as_slice(),
                record.disposition_code,
                record.timestamp_millis,
            ],
        )?;
        Ok(())
    }

    async fn get_resume(&self, ticket_id: [u8; 16]) -> Result<Option<ResumeRecord>, StorageError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT session_id, peer_id, resume_secret, last_sequence, expires_at_millis FROM resume_state WHERE ticket_id = ?1",
                params![ticket_id.as_slice()],
                |row| {
                    let session_id: Vec<u8> = row.get(0)?;
                    let peer_id: Vec<u8> = row.get(1)?;
                    let resume_secret: Vec<u8> = row.get(2)?;
                    let last_sequence = row.get(3)?;
                    let expires_at_millis = row.get(4)?;
                    Ok(ResumeRecord {
                        ticket_id,
                        session_id: SessionId::from(session_id.try_into().unwrap_or([0; 16])),
                        peer_id: PeerId::from(peer_id.try_into().unwrap_or([0; 32])),
                        resume_secret: resume_secret.try_into().unwrap_or([0; 32]),
                        last_sequence,
                        expires_at_millis,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    async fn put_resume(&self, record: ResumeRecord) -> Result<(), StorageError> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT OR REPLACE INTO resume_state(ticket_id, session_id, peer_id, resume_secret, last_sequence, expires_at_millis) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.ticket_id.as_slice(),
                record.session_id.as_bytes().as_slice(),
                record.peer_id.as_bytes().as_slice(),
                record.resume_secret.as_slice(),
                record.last_sequence,
                record.expires_at_millis,
            ],
        )?;
        Ok(())
    }

    async fn latest_audit_hash(&self) -> Result<Option<[u8; 32]>, StorageError> {
        let connection = self.connection()?;
        let hash: Option<Vec<u8>> = connection
            .query_row(
                "SELECT receipt_hash FROM audit_chain ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(hash.map(|hash| hash.try_into().unwrap_or([0; 32])))
    }

    async fn append_audit(
        &self,
        receipt: &AuditReceipt,
        receipt_hash: [u8; 32],
    ) -> Result<(), StorageError> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO audit_chain(receipt_bytes, receipt_hash) VALUES (?1, ?2)",
            params![receipt.encode()?.to_vec(), receipt_hash.as_slice()],
        )?;
        Ok(())
    }

    async fn cache_registry(&self, registry: &CompiledRegistry) -> Result<(), StorageError> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO registry_cache(id, compiled_json) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET compiled_json = excluded.compiled_json",
            params![serde_json::to_string_pretty(registry)?],
        )?;
        Ok(())
    }

    async fn load_registry(&self) -> Result<Option<CompiledRegistry>, StorageError> {
        let connection = self.connection()?;
        let json: Option<String> = connection
            .query_row(
                "SELECT compiled_json FROM registry_cache WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match json {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn sqlite_storage_roundtrip() {
        let file = NamedTempFile::new().expect("temp file");
        let storage = SqliteStorage::open(file.path()).expect("storage");
        let record = DedupRecord {
            peer_id: PeerId::from([1; 32]),
            operation_id: OperationId::from([2; 16]),
            message_id: MessageId::from([3; 16]),
            disposition_code: 1,
            timestamp_millis: 4,
        };
        storage.put_dedup(record.clone()).await.expect("put");
        let loaded = storage
            .get_dedup(record.peer_id, record.operation_id)
            .await
            .expect("get")
            .expect("record");
        assert_eq!(loaded.message_id, record.message_id);
    }
}
