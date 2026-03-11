use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::net::{TcpListener, UnixListener};
use vanta_crypto::IdentityKeypair;
use vanta_registry::CompiledRegistry;
use vanta_runtime::{
    AllowAllTrustResolver, OsRandom, Session, SessionConfig, SessionEvent, SystemClock, Transport,
};
use vanta_storage::{SqliteStorage, Storage};
use vanta_transport::{FramedIoTransport, accept_websocket};
use vanta_wire::{BinaryCodec, Frame, FrameType, WireRole};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeMode {
    Endpoint,
    Relay,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub tcp_addr: Option<String>,
    pub websocket_addr: Option<String>,
    pub unix_socket_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub mode: NodeMode,
    pub listeners: ListenerConfig,
    pub sqlite_path: String,
    pub registry: CompiledRegistry,
    pub identity_seed_hex: String,
}

impl DaemonConfig {
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&contents)?)
    }

    pub fn identity(&self) -> IdentityKeypair {
        let seed_bytes: [u8; 32] = hex::decode(&self.identity_seed_hex)
            .unwrap_or_default()
            .try_into()
            .unwrap_or([0; 32]);
        IdentityKeypair::from_bytes(seed_bytes)
    }
}

pub struct Daemon<S>
where
    S: Storage,
{
    config: DaemonConfig,
    storage: Arc<S>,
}

impl Daemon<SqliteStorage> {
    pub fn open(config: DaemonConfig) -> Result<Self> {
        let storage = SqliteStorage::open(&config.sqlite_path)?;
        Ok(Self {
            config,
            storage: Arc::new(storage),
        })
    }
}

impl<S> Daemon<S>
where
    S: Storage + 'static,
{
    pub async fn run(self) -> Result<()> {
        if let Some(addr) = &self.config.listeners.tcp_addr {
            self.run_tcp(addr).await?;
        }
        if let Some(addr) = &self.config.listeners.websocket_addr {
            self.run_websocket(addr).await?;
        }
        if let Some(path) = &self.config.listeners.unix_socket_path {
            self.run_unix(path).await?;
        }
        Ok(())
    }

    async fn run_tcp(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        loop {
            let (stream, _) = listener.accept().await?;
            let session = self.new_session();
            tokio::spawn(async move {
                let transport = FramedIoTransport::new(stream, "tcp");
                if let Err(error) = serve_connection(session, transport).await {
                    eprintln!("tcp session error: {error}");
                }
            });
        }
    }

    async fn run_websocket(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        loop {
            let (stream, _) = listener.accept().await?;
            let session = self.new_session();
            tokio::spawn(async move {
                let transport = accept_websocket(stream).await?;
                serve_connection(session, transport).await
            });
        }
    }

    async fn run_unix(&self, path: &str) -> Result<()> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        loop {
            let (stream, _) = listener.accept().await?;
            let session = self.new_session();
            tokio::spawn(async move {
                let transport = FramedIoTransport::new(stream, "unix");
                if let Err(error) = serve_connection(session, transport).await {
                    eprintln!("unix session error: {error}");
                }
            });
        }
    }

    fn new_session(&self) -> Session<S, AllowAllTrustResolver, SystemClock, OsRandom> {
        Session::new(SessionConfig {
            role: match self.config.mode {
                NodeMode::Endpoint => WireRole::Responder,
                NodeMode::Relay => WireRole::Relay,
            },
            identity: self.config.identity(),
            registry: self.config.registry.clone(),
            storage: self.storage.clone(),
            trust_resolver: Arc::new(AllowAllTrustResolver),
            clock: Arc::new(SystemClock),
            random: Arc::new(OsRandom),
            max_frame_size: 1024 * 1024,
        })
    }
}

pub async fn serve_connection<S, T>(
    mut session: Session<S, AllowAllTrustResolver, SystemClock, OsRandom>,
    mut transport: T,
) -> Result<()>
where
    S: Storage + 'static,
    T: Transport,
{
    let hello = session.build_hello_frame()?;
    transport.send(&hello).await?;
    loop {
        let frame = transport.recv().await?;
        let events = session.accept_frame(frame).await?;
        for event in events {
            match event {
                SessionEvent::Outbound(frame) => transport.send(&frame).await?,
                SessionEvent::RequestReceived(message_id, payload) => {
                    let response = session.build_response_frame(
                        message_id,
                        payload,
                        vanta_wire::DispositionCode::Applied,
                    )?;
                    transport.send(&response).await?;
                }
                SessionEvent::CommandApplied(command, receipt) => {
                    let receipt_frame = Frame::new(
                        FrameType::AuditReceipt,
                        vanta_wire::FrameFlags::CTRL,
                        receipt.encode()?,
                    );
                    transport.send(&receipt_frame).await?;
                    let response = session.build_response_frame(
                        command.message_id,
                        command.payload,
                        receipt.disposition_code,
                    )?;
                    transport.send(&response).await?;
                }
                _ => {}
            }
        }
    }
}
