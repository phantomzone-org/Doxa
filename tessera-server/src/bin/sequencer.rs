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

	// Start sequencer (spawns prover internally, polls on-chain events).
	let mut sequencer = Sequencer::new(config);
	// println!("genesis_consumed_root: {:?}",
	// contract::hash_to_bytes32(&SequencerState::genesis_consumed_root()));
	sequencer.run().await?;

	Ok(())
}
