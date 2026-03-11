use clap::Parser;
use vanta_daemon::{Daemon, DaemonConfig};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = DaemonConfig::from_toml_file(&args.config)?;
    let daemon = Daemon::open(config)?;
    daemon.run().await
}
