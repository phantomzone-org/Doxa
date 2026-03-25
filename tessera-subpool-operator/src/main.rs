mod config;
mod operator;

use anyhow::Result;
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

    tracing::info!(
        sequencer = %config.sequencer_url,
        poll_secs = config.poll_interval.as_secs(),
        "subpool operator started"
    );

    let http = reqwest::Client::new();
    let mut interval = tokio::time::interval(config.poll_interval);

    loop {
        interval.tick().await;

        if let Err(e) =
            operator::process_pending(&pool, &approval_sk, &config.sequencer_url, &http).await
        {
            tracing::error!("operator tick failed: {e:#}");
        }
    }
}
