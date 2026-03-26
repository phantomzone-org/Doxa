mod config;
mod deposits;
mod operator;
mod spend_txs;

use anyhow::Result;
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use tessera_client::schnorr::PrivateKey;
use tessera_subpool_database::db::create_pool;
use tracing_subscriber::EnvFilter;

use config::OperatorConfig;

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
    let key_bytes = hex::decode(&config.approval_private_key)
        .map_err(|e| anyhow::anyhow!("APPROVAL_PRIVATE_KEY invalid hex: {e}"))?;
    let approval_sk = PrivateKey::decode_reduce(&key_bytes);

    let pool = create_pool(&config.database_url, config.db_max_connections).await?;

    // Alloy provider for broadcasting raw transactions on-chain.
    let rpc_provider = ProviderBuilder::new()
        .connect_http(config.rpc_url.parse()?);

    let subpool_id = config.subpool_id;
    let rollup_address: Address = config.rollup_address.parse()
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

        if let Err(e) =
            operator::process_pending(&pool, &approval_sk, &config.sequencer_url, &http, subpool_id).await
        {
            tracing::error!("freshacc tick failed: {e:#}");
        }

        if let Err(e) =
            deposits::process_pending_deposits(
                &pool,
                &approval_sk,
                &config.sequencer_url,
                &http,
                &rpc_provider,
                subpool_id,
            )
            .await
        {
            tracing::error!("deposit tick failed: {e:#}");
        }

        if let Err(e) =
            deposits::confirm_pending_notes(&pool, &rpc_provider, rollup_address).await
        {
            tracing::error!("confirm_notes tick failed: {e:#}");
        }

        if let Err(e) =
            spend_txs::process_pending_spend_txs(
                &pool,
                &approval_sk,
                &config.sequencer_url,
                &http,
                subpool_id,
            )
            .await
        {
            tracing::error!("spend_tx tick failed: {e:#}");
        }

        if let Err(e) =
            spend_txs::poll_incoming_notes(
                &pool,
                &config.sequencer_url,
                &http,
                subpool_id,
            )
            .await
        {
            tracing::error!("incoming_notes tick failed: {e:#}");
        }
    }
}
