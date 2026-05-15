//! Standalone aggregation prover service.
//!
//! Accepts `POST /prove-node` requests from a coordinator, proves one
//! internal aggregation node, and returns the proof bytes.
//!
//! ## Usage
//!
//! ```bash
//! TESSERA_AGGREGATOR_ARTIFACTS_PATH=tessera-server/artifacts/associated-input-aggregator \
//! TESSERA_AGGREGATION_PROVER_ADDR=0.0.0.0:8092 \
//! cargo run --bin aggregation_prover --release
//! ```

use std::sync::Arc;

use anyhow::Result;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use tessera_server::{
	aggregation_pipeline::types::{ProveNodeRequest, ProveNodeResponse},
	config::AggregatorProverConfig,
};
use tessera_trees::{
	proof_aggregation::{GenericAggregator, LocalNodeProver, NodeProver},
	ConfigNative, ProofNative, D, F,
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState {
	aggregator: Arc<GenericAggregator<F, ConfigNative, D>>,
}

async fn prove_node_handler(
	State(state): State<AppState>,
	Json(req): Json<ProveNodeRequest>,
) -> Result<Json<ProveNodeResponse>, StatusCode> {
	let agg = state.aggregator.clone();

	let result = tokio::task::spawn_blocking(move || -> Result<ProveNodeResponse> {
		// 1. Determine CommonCircuitData for child deserialisation.
		let child_common = if req.level == 0 {
			agg.leaf_common().clone()
		} else {
			agg.level_circuit(req.level - 1)
				.map_err(|e| anyhow::anyhow!("level {} out of range: {e}", req.level - 1))?
				.circuit_data
				.common
				.clone()
		};

		// 2. Deserialise children.
		let children = req
			.children
			.iter()
			.map(|h| {
				let bytes = hex::decode(h).map_err(|e| anyhow::anyhow!("hex decode error: {e}"))?;
				ProofNative::from_bytes(bytes, &child_common)
					.map_err(|e| anyhow::anyhow!("child deserialisation failed: {e:?}"))
			})
			.collect::<Result<Vec<_>>>()?;

		// 3. Prove using LocalNodeProver.
		let local = LocalNodeProver::new(agg.clone());
		let proof = local.prove_node_blocking(req.level, req.node_idx, children)?;

		// 4. Serialise result.
		Ok(ProveNodeResponse {
			proof: hex::encode(proof.to_bytes()),
		})
	})
	.await
	.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
	.map_err(|e| {
		error!("{e}");
		StatusCode::INTERNAL_SERVER_ERROR
	})?;

	Ok(Json(result))
}

#[tokio::main]
async fn main() -> Result<()> {
	dotenvy::dotenv().ok();

	tracing_subscriber::fmt()
		.with_env_filter(
			EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
		)
		.init();

	let config = AggregatorProverConfig::from_env()?;

	info!(path = %config.artifacts_path.display(), "loading aggregator artifacts");
	let agg = GenericAggregator::<F, ConfigNative, D>::from_artifacts(
		&config.artifacts_path,
		&tessera_client::TesseraGateSerializer,
	)?;
	let state = AppState {
		aggregator: Arc::new(agg),
	};

	let app = Router::new()
		.route("/prove-node", post(prove_node_handler))
		.with_state(state);

	let listener = tokio::net::TcpListener::bind(&config.api_bind_addr).await?;
	info!(addr = %config.api_bind_addr, "aggregation prover listening");
	axum::serve(listener, app).await?;
	Ok(())
}
