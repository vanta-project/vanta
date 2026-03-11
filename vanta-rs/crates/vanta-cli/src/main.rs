use anyhow::{Result, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};
use sha2::{Digest, Sha256};
use std::fs;
use std::sync::Arc;
use tokio::net::{TcpStream, UnixStream};
use vanta_crypto::{
    IdentityKeypair, receipt_hash, sign_payload, transcript_hash_for_messages, verify_signature,
};
use vanta_daemon::{Daemon, DaemonConfig};
use vanta_registry::{SignedRegistryManifest, compile_manifest};
use vanta_runtime::{
    AllowAllTrustResolver, OsRandom, Session, SessionConfig, SessionEvent, SystemClock, Transport,
};
use vanta_storage::MemoryStorage;
use vanta_transport::FramedIoTransport;
use vanta_wire::{
    AuditReceipt, AuditReceiptId, BinaryCodec, DispositionCode, Extension, ExtensionCode,
    ExtensionType, Frame, FrameFlags, FrameType, HeartbeatPayload, HelloPayload, MessageId,
    OperationId, PeerId, SessionId, StreamId, TransportProfile, Version, WireRole,
};

#[derive(Parser)]
#[command(name = "vanta")]
#[command(about = "Vanta v0 reference operator CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Keygen,
    CompileRegistry {
        manifest: String,
    },
    InspectFrame {
        input: Option<String>,
        #[arg(long)]
        hex: bool,
        #[arg(long, value_enum)]
        sample: Option<SampleFrameKind>,
        #[arg(long)]
        output: Option<String>,
    },
    VerifyAudit {
        receipt: String,
        #[arg(long)]
        previous_hash_hex: Option<String>,
    },
    GenerateAudit {
        #[arg(long)]
        output: String,
        #[arg(long)]
        hex: bool,
        #[arg(long)]
        previous_hash_hex: Option<String>,
    },
    RunPeer {
        #[arg(long)]
        daemon_config: String,
        #[arg(long, value_enum, default_value = "tcp")]
        transport: PeerTransportKind,
        #[arg(long, value_enum, default_value = "request")]
        action: PeerAction,
        #[arg(long, default_value = "sample-payload")]
        payload: String,
        #[arg(long)]
        identity_seed_hex: Option<String>,
        #[arg(long)]
        operation_id_hex: Option<String>,
        #[arg(long, default_value_t = 1)]
        repeat: u32,
    },
    TranscriptHash {
        messages: Vec<String>,
    },
    RunDaemon {
        config: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SampleFrameKind {
    Hello,
    Request,
    Command,
    Heartbeat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PeerTransportKind {
    Tcp,
    Unix,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum PeerAction {
    Request,
    Command,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen => {
            let identity = IdentityKeypair::generate();
            println!("peer_id={}", identity.peer_id());
            println!("signing_key_base64={}", identity.to_base64());
        }
        Commands::CompileRegistry { manifest } => {
            let manifest = fs::read_to_string(manifest)?;
            let envelope: SignedRegistryManifest = serde_json::from_str(&manifest)?;
            let compiled = compile_manifest(&envelope)?;
            println!("{}", serde_json::to_string_pretty(&compiled)?);
        }
        Commands::InspectFrame {
            input,
            hex,
            sample,
            output,
        } => match (input, sample) {
            (Some(input), None) => inspect_frame(&input, hex)?,
            (None, Some(sample)) => emit_sample_frame(sample, output.as_deref(), hex)?,
            (Some(_), Some(_)) => bail!("use either <input> or --sample, not both"),
            (None, None) => bail!("provide either <input> for decoding or --sample for generation"),
        },
        Commands::VerifyAudit {
            receipt,
            previous_hash_hex,
        } => {
            let bytes = fs::read(receipt)?;
            let receipt = AuditReceipt::decode(&bytes)?;
            let previous_hash = previous_hash_hex
                .map(|value| {
                    let bytes = hex::decode(value)?;
                    let array: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| anyhow!("expected 32-byte previous hash"))?;
                    Ok::<[u8; 32], anyhow::Error>(array)
                })
                .transpose()?;
            let mut unsigned = receipt.clone();
            unsigned.signature = [0; 64];
            let encoded = unsigned.encode()?;
            let hash = receipt_hash(
                &encoded,
                &previous_hash.unwrap_or(receipt.prev_receipt_hash),
            );
            verify_signature(&receipt.receiver_peer_id, &encoded, &receipt.signature)?;
            println!("receipt_hash={}", hex::encode(hash));
        }
        Commands::GenerateAudit {
            output,
            hex,
            previous_hash_hex,
        } => generate_audit(&output, hex, previous_hash_hex.as_deref())?,
        Commands::RunPeer {
            daemon_config,
            transport,
            action,
            payload,
            identity_seed_hex,
            operation_id_hex,
            repeat,
        } => {
            run_peer(
                &daemon_config,
                transport,
                action,
                &payload,
                identity_seed_hex.as_deref(),
                operation_id_hex.as_deref(),
                repeat,
            )
            .await?
        }
        Commands::TranscriptHash { messages } => {
            let owned: Vec<Vec<u8>> = messages
                .into_iter()
                .map(|message| message.into_bytes())
                .collect();
            let refs: Vec<&[u8]> = owned.iter().map(|item| item.as_slice()).collect();
            println!("{}", hex::encode(transcript_hash_for_messages(&refs)));
        }
        Commands::RunDaemon { config } => {
            let config = DaemonConfig::from_toml_file(config)?;
            let daemon = Daemon::open(config)?;
            daemon.run().await?;
        }
    }
    Ok(())
}

fn inspect_frame(input: &str, hex_input: bool) -> Result<()> {
    let bytes = if hex_input {
        hex::decode(fs::read_to_string(input)?.trim())?
    } else {
        fs::read(input)?
    };
    let frame = Frame::decode(&bytes)?;
    println!("{frame:#?}");
    Ok(())
}

fn emit_sample_frame(
    sample: SampleFrameKind,
    output: Option<&str>,
    hex_output: bool,
) -> Result<()> {
    let frame = sample_frame(sample)?;
    let bytes = frame.encode()?;
    match output {
        Some(path) if hex_output => fs::write(path, format!("{}\n", hex::encode(&bytes)))?,
        Some(path) => fs::write(path, &bytes)?,
        None => {
            println!("{}", hex::encode(&bytes));
        }
    }
    eprintln!("generated sample {:?}", sample);
    eprintln!("{frame:#?}");
    Ok(())
}

fn sample_frame(sample: SampleFrameKind) -> Result<Frame> {
    let mut frame = match sample {
        SampleFrameKind::Hello => {
            let payload = HelloPayload {
                role: WireRole::Initiator,
                supported_versions: vec![Version { major: 0, minor: 0 }],
                suite_ids: vec![1],
                max_frame_size: 4096,
                transport_profiles: vec![TransportProfile::Tcp, TransportProfile::WebSocket],
                features: vec!["audit".into(), "resume".into()],
                ordering_bits: 0b111,
            }
            .encode()?;
            Frame::new(FrameType::Hello, FrameFlags::CTRL, payload)
        }
        SampleFrameKind::Request => Frame::new(
            FrameType::Request,
            FrameFlags::ACK_REQ,
            "sample-request".as_bytes().to_vec().into(),
        ),
        SampleFrameKind::Command => {
            let extension = Extension::new(
                ExtensionType::new(ExtensionCode::OperationId as u8, true)?,
                OperationId::from([0x22; 16]).as_bytes().to_vec().into(),
            )?;
            Frame::new(
                FrameType::Command,
                FrameFlags::ACK_REQ,
                "sample-command".as_bytes().to_vec().into(),
            )
            .with_extensions(vec![extension])?
        }
        SampleFrameKind::Heartbeat => {
            let payload = HeartbeatPayload {
                timestamp_millis: 1_700_000_000_000,
                ping_id: 7,
            }
            .encode()?;
            Frame::new(FrameType::Heartbeat, FrameFlags::CTRL, payload)
        }
    };

    frame.header.major_version = 0;
    frame.header.minor_version = 0;
    frame.header.session_id = [0x11; 16];
    frame.header.stream_id = [0x01, 0, 0, 0, 0, 0, 0, 0];
    frame.header.message_id = *MessageId::from([0x33; 16]).as_bytes();
    frame.header.sequence = 1;
    frame.header.schema_token = 0x4180_0011;
    frame.header.capability_token = 0x3220_0011;
    frame.refresh_lengths()?;
    Ok(frame)
}

fn generate_audit(output: &str, hex_output: bool, previous_hash_hex: Option<&str>) -> Result<()> {
    let receiver = IdentityKeypair::from_bytes([0x44; 32]);
    let sender_peer_id = PeerId::from([0x55; 32]);
    let previous_hash = match previous_hash_hex {
        Some(value) => parse_hash32(value)?,
        None => [0u8; 32],
    };

    let payload_hash: [u8; 32] = Sha256::digest(b"sample-command").into();
    let mut receipt = AuditReceipt {
        receipt_id: AuditReceiptId::from([0x66; 16]),
        prev_receipt_hash: previous_hash,
        session_id: SessionId::from([0x11; 16]),
        stream_id: StreamId::from([0x01, 0, 0, 0, 0, 0, 0, 0]),
        message_id: MessageId::from([0x33; 16]),
        operation_id: OperationId::from([0x22; 16]),
        sender_peer_id,
        receiver_peer_id: receiver.peer_id(),
        event_type: 1,
        disposition_code: DispositionCode::Applied,
        payload_hash,
        timestamp_millis: 1_700_000_000_000,
        sequence: 1,
        retransmit_count: 0,
        validation_code: 0,
        signature: [0; 64],
    };

    let unsigned = receipt.encode()?;
    receipt.signature = sign_payload(receiver.signing_key(), &unsigned);
    let encoded = receipt.encode()?;
    let hash = receipt_hash(&unsigned, &receipt.prev_receipt_hash);

    if hex_output {
        fs::write(output, format!("{}\n", hex::encode(&encoded)))?;
    } else {
        fs::write(output, &encoded)?;
    }

    println!("wrote_receipt={output}");
    println!("receiver_peer_id={}", receipt.receiver_peer_id);
    println!("receipt_hash={}", hex::encode(hash));
    Ok(())
}

fn parse_hash32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte hex value"))
}

async fn run_peer(
    daemon_config_path: &str,
    transport_kind: PeerTransportKind,
    action: PeerAction,
    payload: &str,
    identity_seed_hex: Option<&str>,
    operation_id_hex: Option<&str>,
    repeat: u32,
) -> Result<()> {
    let daemon_config = DaemonConfig::from_toml_file(daemon_config_path)?;
    let identity = match identity_seed_hex {
        Some(seed) => IdentityKeypair::from_bytes(parse_seed32(seed)?),
        None => IdentityKeypair::from_bytes([0x77; 32]),
    };

    println!("peer_id={}", identity.peer_id());

    let storage = Arc::new(MemoryStorage::default());
    let mut session = Session::new(SessionConfig {
        role: WireRole::Initiator,
        identity,
        registry: daemon_config.registry.clone(),
        storage,
        trust_resolver: Arc::new(AllowAllTrustResolver),
        clock: Arc::new(SystemClock),
        random: Arc::new(OsRandom),
        max_frame_size: 1024 * 1024,
    });

    let endpoint = match transport_kind {
        PeerTransportKind::Tcp => daemon_config
            .listeners
            .tcp_addr
            .clone()
            .ok_or_else(|| anyhow!("daemon config has no tcp_addr"))?,
        PeerTransportKind::Unix => daemon_config
            .listeners
            .unix_socket_path
            .clone()
            .ok_or_else(|| anyhow!("daemon config has no unix_socket_path"))?,
    };

    let negotiated = match transport_kind {
        PeerTransportKind::Tcp => {
            let stream = TcpStream::connect(&endpoint).await?;
            let mut transport = FramedIoTransport::new(stream, "tcp-client");
            run_peer_session(
                &mut session,
                &mut transport,
                action,
                payload,
                operation_id_hex,
                repeat,
            )
            .await?
        }
        PeerTransportKind::Unix => {
            let stream = UnixStream::connect(&endpoint).await?;
            let mut transport = FramedIoTransport::new(stream, "unix-client");
            run_peer_session(
                &mut session,
                &mut transport,
                action,
                payload,
                operation_id_hex,
                repeat,
            )
            .await?
        }
    };

    println!("session_id={}", negotiated.session_id);
    Ok(())
}

async fn run_peer_session<T: Transport>(
    session: &mut Session<MemoryStorage, AllowAllTrustResolver, SystemClock, OsRandom>,
    transport: &mut T,
    action: PeerAction,
    payload: &str,
    operation_id_hex: Option<&str>,
    repeat: u32,
) -> Result<vanta_runtime::NegotiatedSession> {
    let negotiated = handshake_to_active(session, transport).await?;
    println!(
        "session_active schema_token={} capability_token={}",
        negotiated.schema_token, negotiated.capability_token
    );

    let base_operation_id = match operation_id_hex {
        Some(value) => parse_id16(value)?,
        None => [0x22; 16],
    };

    for index in 0..repeat {
        let frame = match action {
            PeerAction::Request => build_peer_request_frame(
                &negotiated,
                payload.as_bytes(),
                [0x40 + (index as u8); 16],
                index as u64 + 1,
            )?,
            PeerAction::Command => build_peer_command_frame(
                &negotiated,
                payload.as_bytes(),
                [0x50 + (index as u8); 16],
                base_operation_id,
                index as u64 + 1,
            )?,
        };
        transport.send(&frame).await?;
        println!(
            "sent_{:?} message_id={}",
            action,
            MessageId::from(frame.header.message_id)
        );

        match action {
            PeerAction::Request => wait_for_request_response(session, transport).await?,
            PeerAction::Command => wait_for_command_outcome(session, transport).await?,
        }
    }

    Ok(negotiated)
}

async fn handshake_to_active<T: Transport>(
    session: &mut Session<MemoryStorage, AllowAllTrustResolver, SystemClock, OsRandom>,
    transport: &mut T,
) -> Result<vanta_runtime::NegotiatedSession> {
    loop {
        let frame = transport.recv().await?;
        let events = session.accept_frame(frame).await?;
        for event in events {
            match event {
                SessionEvent::Outbound(frame) => {
                    transport.send(&frame).await?;
                }
                SessionEvent::SessionActivated(negotiated) => return Ok(negotiated),
                SessionEvent::Heartbeat(heartbeat) => {
                    println!(
                        "heartbeat ping_id={} timestamp_millis={}",
                        heartbeat.ping_id, heartbeat.timestamp_millis
                    );
                }
                SessionEvent::Error(error) => {
                    bail!("peer handshake received protocol error: {:?}", error);
                }
                _ => {}
            }
        }
    }
}

async fn wait_for_request_response<T: Transport>(
    session: &mut Session<MemoryStorage, AllowAllTrustResolver, SystemClock, OsRandom>,
    transport: &mut T,
) -> Result<()> {
    loop {
        let frame = transport.recv().await?;
        let events = session.accept_frame(frame).await?;
        for event in events {
            match event {
                SessionEvent::ResponseReceived(response) => {
                    println!(
                        "response disposition={:?} payload={}",
                        response.disposition,
                        String::from_utf8_lossy(&response.payload)
                    );
                    return Ok(());
                }
                SessionEvent::Outbound(frame) => transport.send(&frame).await?,
                SessionEvent::Error(error) => bail!("peer received protocol error: {:?}", error),
                _ => {}
            }
        }
    }
}

async fn wait_for_command_outcome<T: Transport>(
    session: &mut Session<MemoryStorage, AllowAllTrustResolver, SystemClock, OsRandom>,
    transport: &mut T,
) -> Result<()> {
    let mut saw_audit = false;
    let mut saw_response = false;

    loop {
        let frame = transport.recv().await?;
        if frame.header.frame_type == FrameType::AuditReceipt {
            let receipt = AuditReceipt::decode(&frame.payload)?;
            println!(
                "audit disposition={:?} receipt_id={} receiver_peer_id={}",
                receipt.disposition_code, receipt.receipt_id, receipt.receiver_peer_id
            );
            saw_audit = true;
            if saw_response {
                return Ok(());
            }
            continue;
        }

        let events = session.accept_frame(frame).await?;
        for event in events {
            match event {
                SessionEvent::ResponseReceived(response) => {
                    println!(
                        "response disposition={:?} payload={}",
                        response.disposition,
                        String::from_utf8_lossy(&response.payload)
                    );
                    saw_response = true;
                    if saw_audit {
                        return Ok(());
                    }
                }
                SessionEvent::Outbound(frame) => transport.send(&frame).await?,
                SessionEvent::Error(error) => bail!("peer received protocol error: {:?}", error),
                _ => {}
            }
        }
    }
}

fn build_peer_request_frame(
    negotiated: &vanta_runtime::NegotiatedSession,
    payload: &[u8],
    message_id: [u8; 16],
    sequence: u64,
) -> Result<Frame> {
    let mut frame = Frame::new(
        FrameType::Request,
        FrameFlags::ACK_REQ,
        payload.to_vec().into(),
    );
    frame.header.major_version = 0;
    frame.header.minor_version = 0;
    frame.header.session_id = *negotiated.session_id.as_bytes();
    frame.header.stream_id = [0; 8];
    frame.header.message_id = message_id;
    frame.header.sequence = sequence;
    frame.header.schema_token = negotiated.schema_token;
    frame.header.capability_token = negotiated.capability_token;
    frame.refresh_lengths()?;
    Ok(frame)
}

fn build_peer_command_frame(
    negotiated: &vanta_runtime::NegotiatedSession,
    payload: &[u8],
    message_id: [u8; 16],
    operation_id: [u8; 16],
    sequence: u64,
) -> Result<Frame> {
    let extension = Extension::new(
        ExtensionType::new(ExtensionCode::OperationId as u8, true)?,
        operation_id.to_vec().into(),
    )?;
    let mut frame = Frame::new(
        FrameType::Command,
        FrameFlags::ACK_REQ,
        payload.to_vec().into(),
    )
    .with_extensions(vec![extension])?;
    frame.header.major_version = 0;
    frame.header.minor_version = 0;
    frame.header.session_id = *negotiated.session_id.as_bytes();
    frame.header.stream_id = [0; 8];
    frame.header.message_id = message_id;
    frame.header.sequence = sequence;
    frame.header.schema_token = negotiated.schema_token;
    frame.header.capability_token = negotiated.capability_token;
    frame.refresh_lengths()?;
    Ok(frame)
}

fn parse_seed32(value: &str) -> Result<[u8; 32]> {
    parse_hash32(value)
}

fn parse_id16(value: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 16-byte hex value"))
}
