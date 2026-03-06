use std::sync::{Arc, Mutex};

use anyhow::Result;
use axum::{
	extract::{DefaultBodyLimit, State},
	routing::post,
	Json, Router,
};
use tessera_server::{
	config::ProverConfig,
	prover::ProverRuntime,
	types::{ProveOutcome, ProveRequest},
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState {
	runtime: Arc<Mutex<ProverRuntime>>,
}

async fn prove_handler(
	State(state): State<AppState>,
	Json(request): Json<ProveRequest>,
) -> Result<Json<ProveOutcome>, axum::http::StatusCode> {
	let runtime = state.runtime.clone();
	let outcome = tokio::task::spawn_blocking(move || {
		let mut guard = runtime.lock().map_err(|_| ())?;
		Ok::<ProveOutcome, ()>(guard.prove_request(request))
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

	let config = ProverConfig::from_env()?;
	let runtime = ProverRuntime::init(
		config.note_batch_size,
		config.account_batch_size,
		config.super_aggregator_artifacts_path,
		config.aggregator_artifacts_path,
		config.aggregation_prover_urls,
		config.aggregation_prover_timeout_secs,
	)?;

	let app_state = AppState {
		runtime: Arc::new(Mutex::new(runtime)),
	};
	let app = Router::new()
		.route("/prove", post(prove_handler))
		.layer(DefaultBodyLimit::max(64 * 1024 * 1024))
		.with_state(app_state);

	let listener = tokio::net::TcpListener::bind(&config.api_bind_addr).await?;
	info!(addr = %config.api_bind_addr, "prover API listening");
	if let Err(e) = axum::serve(listener, app).await {
		error!("prover API server stopped: {e}");
	}
	Ok(())
}
