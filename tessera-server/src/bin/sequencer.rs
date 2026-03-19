use anyhow::Result;
use tessera_server::{config::SequencerConfig, sequencer::Sequencer};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
	// Load .env file if present.
	dotenvy::dotenv().ok();

	// Initialize tracing.
	tracing_subscriber::fmt()
		.with_env_filter(
			EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
		)
		.init();

	// Load config from environment variables.
	let config = SequencerConfig::from_env()?;

	// Start sequencer (polls on-chain events, delegates proving to remote prover API).
	let (mut sequencer, _handle) = Sequencer::new(config);
	sequencer.run().await?;

	Ok(())
}
