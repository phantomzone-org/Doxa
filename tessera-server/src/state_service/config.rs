use alloy::primitives::Address;
use anyhow::{Context, Result};

/// Configuration for the [`StateService`], loaded from environment variables.
///
/// The service shares the same RPC endpoint and contract address as the
/// sequencer; they can be constructed from the same environment.
pub struct StateServiceConfig {
    /// Ethereum JSON-RPC URL (e.g. `http://localhost:8545`).
    pub rpc_url: String,
    /// `ITesseraRollupV2` contract address.
    pub bridge_address: Address,
    /// EVM chain ID.
    pub chain_id: u64,
    /// How often (in seconds) the service polls for newly proven batches.
    ///
    /// Defaults to `12` (one Ethereum slot).
    pub poll_interval_secs: u64,
    /// Maximum block range per `eth_getLogs` call.
    ///
    /// Larger values reduce round-trips; smaller values reduce the risk of
    /// hitting provider limits. Defaults to `1_000`.
    pub log_chunk_blocks: u64,
}

impl StateServiceConfig {
    /// Load configuration from environment variables.
    ///
    /// # Required env vars
    /// - `TESSERA_RPC_URL`: Ethereum JSON-RPC endpoint.
    /// - `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS`: `ITesseraRollupV2` contract address.
    /// - `TESSERA_CHAIN_ID`: EVM chain ID.
    ///
    /// # Optional env vars (with defaults)
    /// - `TESSERA_POLL_INTERVAL_SECS` (default `12`): polling interval in seconds.
    /// - `TESSERA_LOG_CHUNK_BLOCKS` (default `1000`): max blocks per `eth_getLogs` page.
    ///
    /// # Errors
    /// Returns `Err` if any required variable is absent or fails to parse.
    pub fn from_env() -> Result<Self> {
        let rpc_url = std::env::var("TESSERA_RPC_URL").context("TESSERA_RPC_URL not set")?;

        let bridge_address: Address = std::env::var("TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS")
            .context("TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS not set")?
            .parse()
            .context("invalid TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS")?;

        let chain_id: u64 = std::env::var("TESSERA_CHAIN_ID")
            .context("TESSERA_CHAIN_ID not set")?
            .parse()
            .context("invalid TESSERA_CHAIN_ID")?;

        let poll_interval_secs: u64 = std::env::var("TESSERA_POLL_INTERVAL_SECS")
            .unwrap_or_else(|_| "12".to_string())
            .parse()
            .context("invalid TESSERA_POLL_INTERVAL_SECS")?;

        let log_chunk_blocks: u64 = std::env::var("TESSERA_LOG_CHUNK_BLOCKS")
            .unwrap_or_else(|_| "1000".to_string())
            .parse()
            .context("invalid TESSERA_LOG_CHUNK_BLOCKS")?;

        Ok(Self {
            rpc_url,
            bridge_address,
            chain_id,
            poll_interval_secs,
            log_chunk_blocks,
        })
    }
}
