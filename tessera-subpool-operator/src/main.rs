mod config;
mod deposits;
mod operator;
mod spend_txs;

use alloy::primitives::Address;
use anyhow::Result;
use config::OperatorConfig;
use tessera_client::schnorr::PrivateKey;
use tessera_subpool_database::db::create_pool;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
	dotenvy::dotenv().ok();

	tracing_subscriber::fmt()
		.with_env_filter(
			EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
		)
		.init();

	let config = OperatorConfig::from_env()?;

	// Parse approval private key from hex.
	let approval_private_key = config.approval_private_key.trim_start_matches("0x");
	let key_bytes = hex::decode(approval_private_key)
		.map_err(|e| anyhow::anyhow!("APPROVAL_PRIVATE_KEY invalid hex: {e}"))?;
	// TODO: (security alert) this thing parses all 0s secvret key without panic
	let approval_sk = PrivateKey::decode_reduce(&key_bytes);

	let schema_name = format!("subpool_{}", config.subpool_id);
	let pool = create_pool(
		&config.database_url,
		config.db_max_connections,
		&schema_name,
	)
	.await?;

	let subpool_id = config.subpool_id;
	let rollup_address: Address = config
		.rollup_address
		.parse()
		.map_err(|e| anyhow::anyhow!("ROLLUP_ADDRESS invalid: {e}"))?;

	tracing::info!(
		sequencer = %config.sequencer_url,
		rpc = %config.rpc_url,
		poll_secs = config.poll_interval.as_secs(),
		subpool_id,
		"subpool operator started"
	);

	let http = reqwest::Client::new();
	let mut interval = tokio::time::interval(config.poll_interval);

	loop {
		interval.tick().await;

		if let Err(e) = operator::process_pending(
			&pool,
			&approval_sk,
			&config.sequencer_url,
			&http,
			subpool_id,
		)
		.await
		{
			tracing::error!("freshacc tick failed: {e:#}");
		}

		if let Err(e) =
			deposits::run_deposit_checks(&pool, &http, &config.chainalysis_api_key).await
		{
			tracing::error!("deposit check tick failed: {e:#}");
		}

		if let Err(e) = deposits::triage_deposit_reqs_with_approved_deposit_check(&pool).await {
			tracing::error!("deposit triage (approved) failed: {e:#}");
		}

		if let Err(e) = deposits::triage_deposit_reqs_with_rejected_deposit_check(&pool).await {
			tracing::error!("deposit triage (rejected) failed: {e:#}");
		}

		if let Err(e) = deposits::process_approved_deposits(
			&pool,
			&approval_sk,
			&config.sequencer_url,
			&http,
			&config.operator_eth_key,
			&config.rpc_url,
			rollup_address,
		)
		.await
		{
			tracing::error!("deposit process (approved→settled) failed: {e:#}");
		}

		// if let Err(e) = deposits::confirm_pending_notes(&pool, &rpc_provider,
		// rollup_address).await {
		// 	tracing::error!("confirm_notes tick failed: {e:#}");
		// }

		if let Err(e) = spend_txs::run_output_note_checks(&pool).await {
			tracing::error!("output_note_checks tick failed: {e:#}");
		}

		if let Err(e) =
			spend_txs::triage_spend_txs(&pool, &approval_sk, &config.sequencer_url, &http).await
		{
			tracing::error!("spend_tx tick failed: {e:#}");
		}

		if let Err(e) =
			spend_txs::poll_incoming_notes(&pool, &config.sequencer_url, &http, subpool_id).await
		{
			tracing::error!("incoming_notes tick failed: {e:#}");
		}
	}
}
