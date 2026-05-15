use std::time::Duration;

use alloy::{primitives::Address, providers::ProviderBuilder};
use anyhow::Context;
use axum::{routing::get, Router};
use tessera_state_sync::{api::*, StateSyncService};
use tower_http::cors::CorsLayer;
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Read configuration from environment
    let rpc_url = std::env::var("TESSERA_RPC_URL")
        .context("TESSERA_RPC_URL environment variable not set")?;
    let contract_address: Address = std::env::var("TESSERA_CONTRACT_ADDRESS")
        .context("TESSERA_CONTRACT_ADDRESS environment variable not set")?
        .parse()
        .context("invalid TESSERA_CONTRACT_ADDRESS")?;

    let poll_interval_secs: u64 = std::env::var("TESSERA_STATE_SYNC_POLL_INTERVAL")
        .unwrap_or_else(|_| "12".to_string())
        .parse()
        .context("invalid TESSERA_STATE_SYNC_POLL_INTERVAL")?;

    let bind_addr = std::env::var("TESSERA_STATE_SYNC_BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3001".to_string());

    // Create provider
    let provider = ProviderBuilder::new().connect_http(
        rpc_url.parse().context("invalid RPC URL")?,
    );

    // Perform genesis sync
    info!("Starting genesis sync...");
    let service = StateSyncService::sync_from_genesis(
        provider.clone(),
        contract_address,
        1_000, // LOG_FETCH_CHUNK_BLOCKS
    ).await.context("genesis sync failed")?;

    info!("Genesis sync completed. Starting HTTP server...");

    // Start HTTP server
    let app = Router::new()
        .route("/commitment/merkle-path", get(get_commitment_merkle_path))
        .route("/nullifier/status", get(get_nullifier_status))
        .route("/subpool/full-proof", get(get_subpool_full_proof))
        .route("/batch/status", get(get_batch_status))
        .route("/deposits", get(get_deposits))
        .with_state(service.clone())
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind to {}", bind_addr))?;

    info!("HTTP server listening on {}", bind_addr);

    // Start background polling task
    let poll_service = service.clone();
    let poll_provider = provider.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(poll_interval_secs));
        loop {
            interval.tick().await;
            if let Err(e) = poll_service.poll_sync(poll_provider.clone(), contract_address, 1_000).await {
                error!("Polling sync failed: {}", e);
            }
        }
    });

    // Run HTTP server
    axum::serve(listener, app)
        .await
        .context("HTTP server failed")?;

    Ok(())
}