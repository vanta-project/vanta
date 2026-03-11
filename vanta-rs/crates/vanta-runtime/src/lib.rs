use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use thiserror::Error;
use vanta_crypto::{
    CryptoError, EphemeralKeypair, IdentityKeypair, SessionKeys, Transcript, build_auth_finish,
    build_auth_init, derive_session_keys, receipt_hash, verify_auth_finish, verify_auth_init,
};
use vanta_registry::CompiledRegistry;
use vanta_storage::{DedupRecord, ResumeRecord, Storage, StorageError};
use vanta_wire::{
    AckPayload, AuditReceipt, AuditReceiptId, BinaryCodec, CapsConfirmPayload, DispositionCode,
    ErrorPayload, Extension, ExtensionCode, ExtensionType, FlowCreditPayload, Frame, FrameFlags,
    FrameType, HeartbeatPayload, HelloPayload, MessageId, NegotiationPayload, OperationId, PeerId,
    SessionId, StreamId, WireError, WireRole,
};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("wire error")]
    Wire(#[from] WireError),
    #[error("crypto error")]
    Crypto(#[from] CryptoError),
    #[error("storage error")]
    Storage(#[from] StorageError),
    #[error("registry mismatch")]
    RegistryMismatch,
    #[error("peer trust rejected")]
    PeerNotTrusted,
    #[error("session is not active")]
    SessionNotActive,
    #[error("transport error: {0}")]
    Transport(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    Hello,
    AuthInit,
    AuthFinish,
    Negotiate,
    CapsConfirm,
    Active,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamOrdering {
    Unordered,
    Ordered,
    KeyOrdered,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeTicket {
    pub ticket_id: [u8; 16],
    pub session_id: SessionId,
    pub peer_id: PeerId,
    pub last_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamHandle {
    pub stream_id: StreamId,
    pub ordering: StreamOrdering,
    pub send_credit_bytes: u64,
    pub send_credit_messages: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandEnvelope {
    pub message_id: MessageId,
    pub operation_id: OperationId,
    pub schema_token: u32,
    pub capability_token: u32,
    pub payload: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseEnvelope {
    pub message_id: MessageId,
    pub correlation_message_id: MessageId,
    pub disposition: DispositionCode,
    pub payload: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedSession {
    pub schema_token: u32,
    pub capability_token: u32,
    pub ordering_bits: u8,
    pub session_id: SessionId,
}

#[async_trait]
pub trait Transport: Send {
    async fn send(&mut self, frame: &Frame) -> Result<(), RuntimeError>;
    async fn recv(&mut self) -> Result<Frame, RuntimeError>;
    fn kind(&self) -> &'static str;
}

pub trait PeerTrustResolver: Send + Sync {
    fn is_trusted(&self, peer_id: &PeerId) -> bool;
}

pub trait AuditVerifier: Send + Sync {
    fn verify(
        &self,
        receipt: &AuditReceipt,
        previous_hash: Option<[u8; 32]>,
    ) -> Result<[u8; 32], RuntimeError>;
}

pub trait Clock: Send + Sync {
    fn now_millis(&self) -> u64;
}

pub trait RandomSource: Send + Sync {
    fn fill(&self, bytes: &mut [u8]);
}

#[derive(Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        now.as_millis() as u64
    }
}

#[derive(Clone)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, bytes: &mut [u8]) {
        use rand::RngCore;
        let mut rng = rand::rng();
        rng.fill_bytes(bytes);
    }
}

#[derive(Clone)]
pub struct AllowAllTrustResolver;

impl PeerTrustResolver for AllowAllTrustResolver {
    fn is_trusted(&self, _peer_id: &PeerId) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct DefaultAuditVerifier {
    verifying_peer: PeerId,
}

impl DefaultAuditVerifier {
    pub fn new(verifying_peer: PeerId) -> Self {
        Self { verifying_peer }
    }
}

impl AuditVerifier for DefaultAuditVerifier {
    fn verify(
        &self,
        receipt: &AuditReceipt,
        previous_hash: Option<[u8; 32]>,
    ) -> Result<[u8; 32], RuntimeError> {
        if receipt.receiver_peer_id != self.verifying_peer {
            return Err(RuntimeError::PeerNotTrusted);
        }
        let mut canonical = receipt.clone();
        canonical.signature = [0; 64];
        let encoded = canonical.encode()?;
        Ok(receipt_hash(
            &encoded,
            &previous_hash.unwrap_or(receipt.prev_receipt_hash),
        ))
    }
}

#[derive(Clone)]
pub struct SessionConfig<S, T, C, R>
where
    S: Storage,
    T: PeerTrustResolver,
    C: Clock,
    R: RandomSource,
{
    pub role: WireRole,
    pub identity: IdentityKeypair,
    pub registry: CompiledRegistry,
    pub storage: Arc<S>,
    pub trust_resolver: Arc<T>,
    pub clock: Arc<C>,
    pub random: Arc<R>,
    pub max_frame_size: u32,
}

#[derive(Clone, Debug)]
pub enum SessionEvent {
    Outbound(Frame),
    SessionActivated(NegotiatedSession),
    CommandApplied(CommandEnvelope, AuditReceipt),
    ResponseReceived(ResponseEnvelope),
    RequestReceived(MessageId, Bytes),
    EventReceived(MessageId, Bytes),
    Heartbeat(HeartbeatPayload),
    Error(ErrorPayload),
}

pub struct Session<S, T, C, R>
where
    S: Storage,
    T: PeerTrustResolver,
    C: Clock,
    R: RandomSource,
{
    config: SessionConfig<S, T, C, R>,
    phase: SessionPhase,
    transcript: Transcript,
    ephemeral: EphemeralKeypair,
    session_keys: Option<SessionKeys>,
    peer_id: Option<PeerId>,
    session_id: SessionId,
    stream_state: HashMap<StreamId, StreamHandle>,
    outbound_sequence: BTreeMap<StreamId, u64>,
}

impl<S, T, C, R> Session<S, T, C, R>
where
    S: Storage,
    T: PeerTrustResolver,
    C: Clock,
    R: RandomSource,
{
    pub fn new(config: SessionConfig<S, T, C, R>) -> Self {
        Self {
            config,
            phase: SessionPhase::Hello,
            transcript: Transcript::default(),
            ephemeral: EphemeralKeypair::generate(),
            session_keys: None,
            peer_id: None,
            session_id: SessionId::from([0; 16]),
            stream_state: HashMap::new(),
            outbound_sequence: BTreeMap::new(),
        }
    }

    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub fn build_hello_frame(&mut self) -> Result<Frame, RuntimeError> {
        let payload = HelloPayload {
            role: self.config.role,
            supported_versions: vec![vanta_wire::Version { major: 0, minor: 0 }],
            suite_ids: vec![1],
            max_frame_size: self.config.max_frame_size,
            transport_profiles: vec![
                vanta_wire::TransportProfile::Tcp,
                vanta_wire::TransportProfile::WebSocket,
                vanta_wire::TransportProfile::UnixSocket,
                vanta_wire::TransportProfile::Relay,
            ],
            features: vec!["audit".into(), "resume".into(), "relay".into()],
            ordering_bits: 0b111,
        };
        let encoded = payload.encode()?;
        self.transcript.push(&encoded);
        self.phase = SessionPhase::AuthInit;
        Ok(Frame::new(FrameType::Hello, FrameFlags::CTRL, encoded))
    }

    pub fn build_auth_init_frame(&mut self) -> Result<Frame, RuntimeError> {
        let payload = build_auth_init(&self.config.identity, &self.ephemeral, &self.transcript)?;
        let encoded = payload.encode()?;
        self.transcript.push(&encoded);
        self.phase = SessionPhase::AuthFinish;
        Ok(Frame::new(FrameType::Auth, FrameFlags::CTRL, encoded))
    }

    pub fn build_auth_finish_frame(&mut self) -> Result<Frame, RuntimeError> {
        let payload = build_auth_finish(&self.config.identity, &self.ephemeral, &self.transcript)?;
        let encoded = payload.encode()?;
        self.transcript.push(&encoded);
        self.phase = SessionPhase::Negotiate;
        Ok(Frame::new(FrameType::Auth, FrameFlags::CTRL, encoded))
    }

    pub fn build_negotiate_frame(&mut self) -> Result<Frame, RuntimeError> {
        let schemas = self
            .config
            .registry
            .schemas
            .iter()
            .map(|schema| vanta_wire::SchemaDescriptorRef {
                family_id: schema.family_id,
                version_id: schema.version_id,
            })
            .collect();
        let capability_sets = self
            .config
            .registry
            .capabilities
            .iter()
            .map(|capability| capability.capability_id)
            .collect();
        let payload = NegotiationPayload {
            schemas,
            capability_sets,
            extension_namespaces: self.config.registry.extension_namespaces.clone(),
            ordering_bits: 0b111,
        };
        let encoded = payload.encode()?;
        self.transcript.push(&encoded);
        self.phase = SessionPhase::CapsConfirm;
        Ok(Frame::new(FrameType::Negotiate, FrameFlags::CTRL, encoded))
    }

    pub fn build_caps_confirm_frame(&mut self) -> Result<Frame, RuntimeError> {
        let payload = CapsConfirmPayload {
            schema_token: self.config.registry.schema_token,
            capability_token: self.config.registry.capability_token,
            ordering_bits: 0b111,
        };
        let encoded = payload.encode()?;
        self.transcript.push(&encoded);
        self.phase = SessionPhase::Active;
        Ok(Frame::new(FrameType::Caps, FrameFlags::CTRL, encoded))
    }

    pub async fn accept_frame(&mut self, frame: Frame) -> Result<Vec<SessionEvent>, RuntimeError> {
        match frame.header.frame_type {
            FrameType::Hello => {
                let payload = HelloPayload::decode(&frame.payload)?;
                self.transcript.push(&frame.payload);
                self.phase = SessionPhase::AuthInit;
                Ok(vec![
                    SessionEvent::Outbound(self.build_auth_init_frame()?),
                    SessionEvent::Heartbeat(HeartbeatPayload {
                        timestamp_millis: self.config.clock.now_millis(),
                        ping_id: payload.max_frame_size as u64,
                    }),
                ])
            }
            FrameType::Auth => self.handle_auth(frame).await,
            FrameType::Negotiate => {
                let payload = NegotiationPayload::decode(&frame.payload)?;
                if payload.extension_namespaces != self.config.registry.extension_namespaces {
                    return Err(RuntimeError::RegistryMismatch);
                }
                self.transcript.push(&frame.payload);
                Ok(vec![SessionEvent::Outbound(
                    self.build_caps_confirm_frame()?,
                )])
            }
            FrameType::Caps => {
                let payload = CapsConfirmPayload::decode(&frame.payload)?;
                if payload.schema_token != self.config.registry.schema_token
                    || payload.capability_token != self.config.registry.capability_token
                {
                    return Err(RuntimeError::RegistryMismatch);
                }
                self.phase = SessionPhase::Active;
                Ok(vec![SessionEvent::SessionActivated(NegotiatedSession {
                    schema_token: payload.schema_token,
                    capability_token: payload.capability_token,
                    ordering_bits: payload.ordering_bits,
                    session_id: self.session_id,
                })])
            }
            FrameType::Command => self.handle_command(frame).await,
            FrameType::Request => Ok(vec![SessionEvent::RequestReceived(
                MessageId::from(frame.header.message_id),
                frame.payload,
            )]),
            FrameType::Response => {
                let correlation = frame
                    .extensions
                    .iter()
                    .find(|extension| extension.ty.code() == ExtensionCode::CorrelationId as u8)
                    .map(|extension| {
                        let mut value = [0; 16];
                        value.copy_from_slice(&extension.value);
                        MessageId::from(value)
                    })
                    .unwrap_or(MessageId::from([0; 16]));
                Ok(vec![SessionEvent::ResponseReceived(ResponseEnvelope {
                    message_id: MessageId::from(frame.header.message_id),
                    correlation_message_id: correlation,
                    disposition: DispositionCode::Applied,
                    payload: frame.payload,
                })])
            }
            FrameType::Event => Ok(vec![SessionEvent::EventReceived(
                MessageId::from(frame.header.message_id),
                frame.payload,
            )]),
            FrameType::Heartbeat => Ok(vec![SessionEvent::Heartbeat(HeartbeatPayload::decode(
                &frame.payload,
            )?)]),
            FrameType::Error => Ok(vec![SessionEvent::Error(ErrorPayload::decode(
                &frame.payload,
            )?)]),
            FrameType::Ack => {
                let _ = AckPayload::decode(&frame.payload)?;
                Ok(Vec::new())
            }
            FrameType::FlowCredit => {
                let payload = FlowCreditPayload::decode(&frame.payload)?;
                let entry =
                    self.stream_state
                        .entry(payload.target_stream_id)
                        .or_insert(StreamHandle {
                            stream_id: payload.target_stream_id,
                            ordering: StreamOrdering::Unordered,
                            send_credit_bytes: 0,
                            send_credit_messages: 0,
                        });
                entry.send_credit_bytes =
                    entry.send_credit_bytes.saturating_add(payload.credit_bytes);
                entry.send_credit_messages = entry
                    .send_credit_messages
                    .saturating_add(payload.credit_messages);
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }

    async fn handle_auth(&mut self, frame: Frame) -> Result<Vec<SessionEvent>, RuntimeError> {
        match self.phase {
            SessionPhase::AuthInit => {
                let payload = vanta_wire::AuthInitPayload::decode(&frame.payload)?;
                if !self.config.trust_resolver.is_trusted(&payload.peer_id) {
                    return Err(RuntimeError::PeerNotTrusted);
                }
                verify_auth_init(&payload, &self.transcript)?;
                self.peer_id = Some(payload.peer_id);
                self.transcript.push(&frame.payload);
                let shared_secret = self.ephemeral.diffie_hellman(payload.ephemeral_public_key);
                let transcript_hash = self.transcript.finalize();
                let keys = derive_session_keys(shared_secret, transcript_hash)?;
                self.session_id = keys.session_id;
                self.session_keys = Some(keys);
                Ok(vec![SessionEvent::Outbound(
                    self.build_auth_finish_frame()?,
                )])
            }
            SessionPhase::AuthFinish => {
                let payload = vanta_wire::AuthFinishPayload::decode(&frame.payload)?;
                verify_auth_finish(&payload, &self.transcript)?;
                self.peer_id = Some(payload.peer_id);
                self.transcript.push(&frame.payload);
                let shared_secret = self.ephemeral.diffie_hellman(payload.ephemeral_public_key);
                let transcript_hash = self.transcript.finalize();
                let keys = derive_session_keys(shared_secret, transcript_hash)?;
                self.session_id = keys.session_id;
                self.session_keys = Some(keys);
                Ok(vec![SessionEvent::Outbound(self.build_negotiate_frame()?)])
            }
            _ => Ok(Vec::new()),
        }
    }

    async fn handle_command(&mut self, frame: Frame) -> Result<Vec<SessionEvent>, RuntimeError> {
        if self.phase != SessionPhase::Active {
            return Err(RuntimeError::SessionNotActive);
        }
        let peer_id = self.peer_id.unwrap_or(self.config.identity.peer_id());
        let operation_extension = frame
            .extensions
            .iter()
            .find(|extension| extension.ty.code() == ExtensionCode::OperationId as u8)
            .ok_or(RuntimeError::RegistryMismatch)?;
        let mut operation_id = [0; 16];
        operation_id.copy_from_slice(&operation_extension.value);
        let operation_id = OperationId::from(operation_id);

        let existing = self.config.storage.get_dedup(peer_id, operation_id).await?;
        let disposition = if existing.is_some() {
            DispositionCode::DuplicateApplied
        } else {
            let record = DedupRecord {
                peer_id,
                operation_id,
                message_id: MessageId::from(frame.header.message_id),
                disposition_code: DispositionCode::Applied as u16,
                timestamp_millis: self.config.clock.now_millis(),
            };
            self.config.storage.put_dedup(record).await?;
            DispositionCode::Applied
        };

        let command = CommandEnvelope {
            message_id: MessageId::from(frame.header.message_id),
            operation_id,
            schema_token: frame.header.schema_token,
            capability_token: frame.header.capability_token,
            payload: frame.payload.clone(),
        };
        let receipt = self.make_receipt(&frame, disposition).await?;
        let mut unsigned = receipt.clone();
        unsigned.signature = [0; 64];
        let receipt_hash = receipt_hash(&unsigned.encode()?, &receipt.prev_receipt_hash);
        self.config
            .storage
            .append_audit(&receipt, receipt_hash)
            .await?;
        Ok(vec![SessionEvent::CommandApplied(command, receipt)])
    }

    async fn make_receipt(
        &self,
        frame: &Frame,
        disposition: DispositionCode,
    ) -> Result<AuditReceipt, RuntimeError> {
        let previous_hash = self
            .config
            .storage
            .latest_audit_hash()
            .await?
            .unwrap_or([0; 32]);
        let payload_hash: [u8; 32] = Sha256::digest(&frame.payload).into();
        let mut receipt_id = [0; 16];
        receipt_id.copy_from_slice(&Sha256::digest(frame.header.message_id)[..16]);
        let operation_id = frame
            .extensions
            .iter()
            .find(|extension| extension.ty.code() == ExtensionCode::OperationId as u8)
            .map(|extension| {
                let mut value = [0; 16];
                value.copy_from_slice(&extension.value);
                OperationId::from(value)
            })
            .unwrap_or(OperationId::from([0; 16]));
        let mut receipt = AuditReceipt {
            receipt_id: AuditReceiptId::from(receipt_id),
            prev_receipt_hash: previous_hash,
            session_id: self.session_id,
            stream_id: StreamId::from(frame.header.stream_id),
            message_id: MessageId::from(frame.header.message_id),
            operation_id,
            sender_peer_id: self.peer_id.unwrap_or(self.config.identity.peer_id()),
            receiver_peer_id: self.config.identity.peer_id(),
            event_type: 1,
            disposition_code: disposition,
            payload_hash,
            timestamp_millis: self.config.clock.now_millis(),
            sequence: frame.header.sequence,
            retransmit_count: u16::from(frame.header.flags.contains(FrameFlags::RETRANSMIT)),
            validation_code: 0,
            signature: [0; 64],
        };
        let encoded = receipt.encode()?;
        receipt.signature =
            vanta_crypto::sign_payload(self.config.identity.signing_key(), &encoded);
        Ok(receipt)
    }

    pub async fn issue_resume_ticket(
        &self,
        peer_id: PeerId,
        last_sequence: u64,
    ) -> Result<ResumeTicket, RuntimeError> {
        let mut ticket_id = [0; 16];
        self.config.random.fill(&mut ticket_id);
        let resume_secret = self
            .session_keys
            .as_ref()
            .map(|keys| keys.resume_secret)
            .unwrap_or([0; 32]);
        self.config
            .storage
            .put_resume(ResumeRecord {
                ticket_id,
                session_id: self.session_id,
                peer_id,
                resume_secret,
                last_sequence,
                expires_at_millis: self.config.clock.now_millis() + 300_000,
            })
            .await?;
        Ok(ResumeTicket {
            ticket_id,
            session_id: self.session_id,
            peer_id,
            last_sequence,
        })
    }

    pub fn open_stream(&mut self, stream_id: StreamId, ordering: StreamOrdering) -> StreamHandle {
        let handle = StreamHandle {
            stream_id,
            ordering,
            send_credit_bytes: 0,
            send_credit_messages: 0,
        };
        self.stream_state.insert(stream_id, handle.clone());
        handle
    }

    pub fn build_response_frame(
        &mut self,
        correlation_message_id: MessageId,
        payload: Bytes,
        disposition: DispositionCode,
    ) -> Result<Frame, RuntimeError> {
        let extension = Extension::new(
            ExtensionType::new(ExtensionCode::CorrelationId as u8, false)?,
            Bytes::copy_from_slice(correlation_message_id.as_bytes()),
        )?;
        let mut frame = Frame::new(FrameType::Response, FrameFlags::empty(), payload)
            .with_extensions(vec![extension])?;
        frame.header.session_id = *self.session_id.as_bytes();
        frame.header.schema_token = self.config.registry.schema_token;
        frame.header.capability_token = self.config.registry.capability_token;
        frame.header.sequence = self.next_sequence(StreamId::from([0; 8]));
        frame.header.message_id = *correlation_message_id.as_bytes();
        if disposition != DispositionCode::Applied {
            frame.header.flags.insert(FrameFlags::CTRL);
        }
        frame.refresh_lengths()?;
        Ok(frame)
    }

    pub fn next_sequence(&mut self, stream_id: StreamId) -> u64 {
        let entry = self.outbound_sequence.entry(stream_id).or_insert(0);
        *entry += 1;
        *entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vanta_registry::{
        CapabilityManifest, RegistryManifest, SchemaManifest, SignedRegistryManifest,
        compile_manifest,
    };
    use vanta_storage::MemoryStorage;

    #[derive(Clone)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now_millis(&self) -> u64 {
            1_700_000_000_000
        }
    }

    #[derive(Clone)]
    struct FixedRandom;

    impl RandomSource for FixedRandom {
        fn fill(&self, bytes: &mut [u8]) {
            bytes.fill(7);
        }
    }

    fn registry() -> CompiledRegistry {
        compile_manifest(&SignedRegistryManifest {
            manifest: RegistryManifest {
                version: 1,
                name: "test".into(),
                extension_namespaces: vec!["vanta.core".into()],
                schemas: vec![SchemaManifest {
                    family_id_hex: "0102030405060708".into(),
                    version_id: 1,
                    name: "demo.command".into(),
                    fields: vec!["body".into()],
                    optional_fields: vec![],
                }],
                capabilities: vec![CapabilityManifest {
                    set_id_hex: "1112131415161718".into(),
                    name: "mutate".into(),
                    permissions: vec!["command.apply".into()],
                }],
                metadata: BTreeMap::new(),
            },
            signer_peer_id_hex: None,
            signature_base64: None,
        })
        .expect("registry compiles")
    }

    fn session(
        role: WireRole,
        storage: Arc<MemoryStorage>,
        seed: [u8; 32],
    ) -> Session<MemoryStorage, AllowAllTrustResolver, FixedClock, FixedRandom> {
        Session::new(SessionConfig {
            role,
            identity: IdentityKeypair::from_bytes(seed),
            registry: registry(),
            storage,
            trust_resolver: Arc::new(AllowAllTrustResolver),
            clock: Arc::new(FixedClock),
            random: Arc::new(FixedRandom),
            max_frame_size: 4096,
        })
    }

    #[tokio::test]
    async fn handshake_and_command_dedup_work() {
        let storage_a = Arc::new(MemoryStorage::default());
        let storage_b = Arc::new(MemoryStorage::default());
        let mut initiator = session(WireRole::Initiator, storage_a, [1; 32]);
        let mut responder = session(WireRole::Responder, storage_b.clone(), [2; 32]);

        let hello = initiator.build_hello_frame().expect("hello");
        let mut events = responder.accept_frame(hello).await.expect("hello accepted");
        let auth_init = match events.remove(0) {
            SessionEvent::Outbound(frame) => frame,
            _ => panic!("expected auth init"),
        };

        let mut events = initiator
            .accept_frame(auth_init)
            .await
            .expect("auth init accepted");
        let auth_finish = match events.remove(0) {
            SessionEvent::Outbound(frame) => frame,
            _ => panic!("expected auth finish"),
        };

        let mut events = responder
            .accept_frame(auth_finish)
            .await
            .expect("auth finish accepted");
        let negotiate = match events.remove(0) {
            SessionEvent::Outbound(frame) => frame,
            _ => panic!("expected negotiate"),
        };

        let mut events = initiator
            .accept_frame(negotiate)
            .await
            .expect("negotiate accepted");
        let caps = match events.remove(0) {
            SessionEvent::Outbound(frame) => frame,
            _ => panic!("expected caps"),
        };

        responder.accept_frame(caps).await.expect("caps accepted");
        assert_eq!(initiator.phase(), SessionPhase::Active);
        assert_eq!(responder.phase(), SessionPhase::Active);

        let operation_id = OperationId::from([9; 16]);
        let extension = Extension::new(
            ExtensionType::new(ExtensionCode::OperationId as u8, true).expect("extension type"),
            Bytes::copy_from_slice(operation_id.as_bytes()),
        )
        .expect("extension");

        let mut command = Frame::new(
            FrameType::Command,
            FrameFlags::ACK_REQ,
            Bytes::from_static(b"apply"),
        );
        command.header.message_id = [5; 16];
        command.header.schema_token = responder.config.registry.schema_token;
        command.header.capability_token = responder.config.registry.capability_token;
        command.header.session_id = *responder.session_id.as_bytes();
        let command = command
            .with_extensions(vec![extension.clone()])
            .expect("command");

        let mut first = responder
            .accept_frame(command.clone())
            .await
            .expect("command accepted");
        let (_, first_receipt) = match first.remove(0) {
            SessionEvent::CommandApplied(command, receipt) => (command, receipt),
            _ => panic!("expected command applied"),
        };
        assert_eq!(first_receipt.disposition_code, DispositionCode::Applied);

        let mut second = responder
            .accept_frame(command)
            .await
            .expect("duplicate accepted");
        let (_, second_receipt) = match second.remove(0) {
            SessionEvent::CommandApplied(command, receipt) => (command, receipt),
            _ => panic!("expected duplicate command"),
        };
        assert_eq!(
            second_receipt.disposition_code,
            DispositionCode::DuplicateApplied
        );

        let dedup = storage_b
            .get_dedup(initiator.config.identity.peer_id(), operation_id)
            .await
            .expect("storage")
            .expect("record");
        assert_eq!(dedup.disposition_code, DispositionCode::Applied as u16);
    }
}
