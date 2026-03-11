use anyhow::{Result, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};
use sha2::{Digest, Sha256};
use std::fs;
use vanta_crypto::{
    IdentityKeypair, receipt_hash, sign_payload, transcript_hash_for_messages, verify_signature,
};
use vanta_daemon::{Daemon, DaemonConfig};
use vanta_registry::{SignedRegistryManifest, compile_manifest};
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
