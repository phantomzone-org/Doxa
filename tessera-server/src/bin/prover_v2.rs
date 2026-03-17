use std::sync::{Arc, Mutex};

use anyhow::Result;
use axum::{
	extract::{DefaultBodyLimit, State},
	routing::post,
	Json, Router,
};
use tessera_server::{
	config::ProverV2Config,
	prover_v2::ProverRuntimeV2,
	types::{ConsumeOutcome, ConsumeProveRequest, ProveOutcomeV2, ProveRequestV2},
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState {
	runtime: Arc<Mutex<ProverRuntimeV2>>,
}

async fn prove_v2_handler(
	State(state): State<AppState>,
	Json(request): Json<ProveRequestV2>,
) -> Result<Json<ProveOutcomeV2>, axum::http::StatusCode> {
	let runtime = state.runtime.clone();
	let outcome = tokio::task::spawn_blocking(move || {
		let mut guard = runtime.lock().map_err(|_| ())?;
		Ok::<ProveOutcomeV2, ()>(guard.prove_request_v2(request))
	})
	.await
	.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
	.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
	Ok(Json(outcome))
}

async fn prove_consume_handler(
	State(state): State<AppState>,
	Json(request): Json<ConsumeProveRequest>,
) -> Result<Json<ConsumeOutcome>, axum::http::StatusCode> {
	let runtime = state.runtime.clone();
	let outcome = tokio::task::spawn_blocking(move || {
		let mut guard = runtime.lock().map_err(|_| ())?;
		Ok::<ConsumeOutcome, ()>(guard.prove_consume_request(request))
	})
	.await
	.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
	.map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
	Ok(Json(outcome))
}

#[tokio::main]
async fn main() -> Result<()> {
	dotenvy::dotenv().ok();

	tracing_subscriber::fmt()
		.with_env_filter(
			EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
		)
		.init();

	let config = ProverV2Config::from_env()?;
	let runtime = ProverRuntimeV2::init(
		config.sr_artifacts_path,
		config.sr_batch_size,
		config.super_aggregator_v2_artifacts_path,
		config.aggregator_artifacts_path,
		config.aggregation_prover_urls,
		config.aggregation_prover_timeout_secs,
	)?;

	let app_state = AppState {
		runtime: Arc::new(Mutex::new(runtime)),
	};
	let app = Router::new()
		.route("/prove-v2", post(prove_v2_handler))
		.route("/prove-consume", post(prove_consume_handler))
		.layer(DefaultBodyLimit::max(64 * 1024 * 1024))
		.with_state(app_state);

	let listener = tokio::net::TcpListener::bind(&config.api_bind_addr).await?;
	info!(addr = %config.api_bind_addr, "V2 prover API listening");
	if let Err(e) = axum::serve(listener, app).await {
		error!("V2 prover API server stopped: {e}");
	}
	Ok(())
}
