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
	let testing = config.testing;

	// Start sequencer (polls on-chain events, delegates proving to remote prover API).
	let (mut sequencer, handle) = Sequencer::new(config);

	// When TESSERA_TESTING=1, spawn a thin HTTP server so shell scripts can drive the
	// sequencer via curl without a real prover or on-chain Pending deposits.
	if testing {
		let addr: std::net::SocketAddr = std::env::var("TESSERA_TEST_API_ADDR")
			.unwrap_or_else(|_| "127.0.0.1:8081".to_string())
			.parse()?;
		let h = handle.clone();
		tokio::spawn(async move {
			test_api::serve(h, addr).await;
		});
	}

	sequencer.run().await?;

	Ok(())
}

/// Thin axum HTTP server exposing test-only endpoints.
///
/// Enabled only when `TESSERA_TESTING=1`.  All routes forward directly into the
/// [`SequencerHandle`] so no separate process or channel wiring is required.
mod test_api {
	use axum::{extract::State, routing::post, Json, Router};
	use serde::{Deserialize, Serialize};
	use tessera_server::sequencer::SequencerHandle;

	// -------------------------------------------------------------------------
	// Shared state
	// -------------------------------------------------------------------------

	#[derive(Clone)]
	struct AppState {
		handle: SequencerHandle,
	}

	// -------------------------------------------------------------------------
	// Request / response types
	// -------------------------------------------------------------------------

	#[derive(Deserialize)]
	struct DepositBody {
		/// Hex-encoded 32-byte note commitment (with or without `0x` prefix).
		note_commitment: String,
	}

	#[derive(Deserialize)]
	struct TxBody {
		/// Account nullifier leaf (hex, 32 bytes).
		an: String,
		/// Account commitment leaf (hex, 32 bytes).
		ac: String,
		/// Note nullifiers — 8 entries (hex, 32 bytes each).
		nn: [String; 8],
		/// Note commitments — 8 entries (hex, 32 bytes each).
		nc: [String; 8],
	}

	#[derive(Serialize)]
	struct Resp {
		accepted: bool,
		#[serde(skip_serializing_if = "Option::is_none")]
		error: Option<String>,
	}

	fn ok() -> Json<Resp> {
		Json(Resp {
			accepted: true,
			error: None,
		})
	}

	fn err(msg: impl std::fmt::Display) -> Json<Resp> {
		Json(Resp {
			accepted: false,
			error: Some(msg.to_string()),
		})
	}

	// -------------------------------------------------------------------------
	// Hex parsing helper
	// -------------------------------------------------------------------------

	fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
		let s = s.strip_prefix("0x").unwrap_or(s);
		let bytes = hex::decode(s)?;
		bytes
			.try_into()
			.map_err(|_| anyhow::anyhow!("expected exactly 32 bytes"))
	}

	// -------------------------------------------------------------------------
	// Handlers
	// -------------------------------------------------------------------------

	/// `POST /test/deposits`
	///
	/// Submit a deposit note commitment without the on-chain Pending check.
	async fn test_deposit(State(s): State<AppState>, Json(body): Json<DepositBody>) -> Json<Resp> {
		let note = match parse_hex32(&body.note_commitment) {
			Ok(v) => v,
			Err(e) => return err(e),
		};
		match s.handle.test_submit_deposit(note).await {
			Ok(()) => ok(),
			Err(e) => err(e),
		}
	}

	/// `POST /test/deposits/validate`
	///
	/// Flush the pending deposit batch on-chain and confirm it with a zero proof.
	/// Blocks until the on-chain `proveDepositBatch` transaction is confirmed.
	async fn test_deposits_validate(State(s): State<AppState>) -> Json<Resp> {
		match s.handle.test_validate_deposits().await {
			Ok(()) => ok(),
			Err(e) => err(e),
		}
	}

	/// `POST /test/transactions`
	///
	/// Submit a transaction slot with raw leaf values — no Plonky2 proof required.
	async fn test_tx(State(s): State<AppState>, Json(body): Json<TxBody>) -> Json<Resp> {
		let an = match parse_hex32(&body.an) {
			Ok(v) => v,
			Err(e) => return err(format!("an: {e}")),
		};
		let ac = match parse_hex32(&body.ac) {
			Ok(v) => v,
			Err(e) => return err(format!("ac: {e}")),
		};
		let mut nn = [[0u8; 32]; 8];
		for (i, s_val) in body.nn.iter().enumerate() {
			nn[i] = match parse_hex32(s_val) {
				Ok(v) => v,
				Err(e) => return err(format!("nn[{i}]: {e}")),
			};
		}
		let mut nc = [[0u8; 32]; 8];
		for (i, s_val) in body.nc.iter().enumerate() {
			nc[i] = match parse_hex32(s_val) {
				Ok(v) => v,
				Err(e) => return err(format!("nc[{i}]: {e}")),
			};
		}
		match s.handle.test_submit_tx(an, ac, nn, nc).await {
			Ok(()) => ok(),
			Err(e) => err(e),
		}
	}

	/// `POST /test/transactions/validate`
	///
	/// Flush the pending TX batch on-chain and confirm it with a zero proof.
	/// Blocks until the on-chain `proveTransactionBatch` transaction is confirmed.
	async fn test_tx_validate(State(s): State<AppState>) -> Json<Resp> {
		match s.handle.test_validate_txs().await {
			Ok(()) => ok(),
			Err(e) => err(e),
		}
	}

	/// `GET /health` — liveness probe used by scripts to wait for readiness.
	async fn health() -> Json<serde_json::Value> {
		Json(serde_json::json!({"ok": true}))
	}

	// -------------------------------------------------------------------------
	// Server entry point
	// -------------------------------------------------------------------------

	pub async fn serve(handle: SequencerHandle, addr: std::net::SocketAddr) {
		let state = AppState {
			handle,
		};
		let app = Router::new()
			.route("/health", axum::routing::get(health))
			.route("/test/deposits", post(test_deposit))
			.route("/test/deposits/validate", post(test_deposits_validate))
			.route("/test/transactions", post(test_tx))
			.route("/test/transactions/validate", post(test_tx_validate))
			.with_state(state);

		let listener = tokio::net::TcpListener::bind(addr)
			.await
			.expect("failed to bind test API");
		tracing::info!(%addr, "test API server listening (TESSERA_TESTING=1)");
		axum::serve(listener, app)
			.await
			.expect("test API server error");
	}
}
