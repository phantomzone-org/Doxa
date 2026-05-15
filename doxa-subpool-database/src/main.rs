use anyhow::Result;
use doxa_subpool_database::{config::AppConfig, db::create_pool, routes, state::AppState};
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
	dotenvy::dotenv().ok();

	tracing_subscriber::fmt()
		.with_env_filter(
			EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
		)
		.init();

	let config = AppConfig::from_env()?;
	let subpool_id = std::env::var("SUBPOOL_ID").unwrap_or_else(|_| "1".to_string());
	let schema_name = format!("subpool_{subpool_id}");
	let pool = create_pool(
		&config.database_url,
		config.db_max_connections,
		&schema_name,
	)
	.await?;

	sqlx::migrate!("./migrations").run(&pool).await?;

	let state = AppState {
		pool,
		faucet_private_key: config.faucet_private_key,
		sepolia_rpc_url: config.sepolia_rpc_url,
		usdx_contract_addr: config.usdx_contract_addr,
		subpool_id: config.subpool_id,
	};
	let app = routes::router(state)
		.layer(TraceLayer::new_for_http())
		.layer(CorsLayer::permissive());

	let listener = TcpListener::bind(&config.api_bind_addr).await?;
	tracing::info!(
		"subpool_id={:?}, listening on {}",
		config.subpool_id,
		config.api_bind_addr
	);
	axum::serve(listener, app).await?;

	Ok(())
}
