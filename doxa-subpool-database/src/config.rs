use anyhow::{Context, Result};
use plonky2_field::{goldilocks_field::GoldilocksField, types::Field};
use doxa_client::SubpoolId;

type F = GoldilocksField;

pub struct AppConfig {
	/// PostgreSQL connection string. Env: DATABASE_URL (required).
	pub database_url: String,
	/// HTTP bind address. Env: DOXA_SUBPOOL_API_ADDR (default "0.0.0.0:8080").
	pub api_bind_addr: String,
	/// Max DB connections in pool. Env: DATABASE_MAX_CONNECTIONS (default 10).
	pub db_max_connections: u32,
	/// Faucet wallet private key (hex, with or without `0x`). Env: FAUCET_PRIVATE_KEY (required).
	pub faucet_private_key: String,
	/// Sepolia RPC URL. Env: SEPOLIA_RPC_URL (required).
	pub sepolia_rpc_url: String,
	/// Deployed ToyUSDTWOperator contract address. Env: USDX_CONTRACT_ADDR (required).
	pub usdx_contract_addr: String,
	/// Subpool identifier. Env: SUBPOOL_ID (default 1).
	pub subpool_id: SubpoolId,
}

impl AppConfig {
	pub fn from_env() -> Result<Self> {
		let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL not set")?;

		let api_bind_addr = std::env::var("DOXA_SUBPOOL_API_ADDR")
			.unwrap_or_else(|_| "0.0.0.0:8080".to_string());

		let db_max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
			.unwrap_or_else(|_| "10".to_string())
			.parse::<u32>()
			.context("DATABASE_MAX_CONNECTIONS must be a positive integer")?;

		let faucet_private_key =
			std::env::var("FAUCET_PRIVATE_KEY").context("FAUCET_PRIVATE_KEY not set")?;
		let sepolia_rpc_url =
			std::env::var("SEPOLIA_RPC_URL").context("SEPOLIA_RPC_URL not set")?;
		let usdx_contract_addr =
			std::env::var("USDX_CONTRACT_ADDR").context("USDX_CONTRACT_ADDR not set")?;

		let subpool_id = SubpoolId(F::from_canonical_u64(
			std::env::var("SUBPOOL_ID")
				.unwrap_or_else(|_| "1".to_string())
				.parse::<u64>()
				.context("SUBPOOL_ID must be a u64")?,
		));

		Ok(Self {
			database_url,
			api_bind_addr,
			db_max_connections,
			faucet_private_key,
			sepolia_rpc_url,
			usdx_contract_addr,
			subpool_id,
		})
	}
}
