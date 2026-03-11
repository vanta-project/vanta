use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use std::fs;
use vanta_crypto::{IdentityKeypair, transcript_hash_for_messages, verify_signature};
use vanta_daemon::{Daemon, DaemonConfig};
use vanta_registry::{SignedRegistryManifest, compile_manifest};
use vanta_wire::{AuditReceipt, BinaryCodec, Frame};

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
        input: String,
        #[arg(long)]
        hex: bool,
    },
    VerifyAudit {
        receipt: String,
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
        Commands::InspectFrame { input, hex } => {
            let bytes = if hex {
                hex::decode(fs::read_to_string(input)?.trim())?
            } else {
                fs::read(input)?
            };
            let frame = Frame::decode(&bytes)?;
            println!("{frame:#?}");
        }
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
            let hash = vanta_crypto::receipt_hash(
                &encoded,
                &previous_hash.unwrap_or(receipt.prev_receipt_hash),
            );
            verify_signature(&receipt.receiver_peer_id, &encoded, &receipt.signature)?;
            println!("receipt_hash={}", hex::encode(hash));
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
