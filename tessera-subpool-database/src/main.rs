use anyhow::Result;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use tessera_subpool_database::{
    config::AppConfig,
    db::create_pool,
    routes,
    state::AppState,
};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = AppConfig::from_env()?;
    let pool = create_pool(&config.database_url, config.db_max_connections).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    let state = AppState { pool };
    let app = routes::router(state);

    let listener = TcpListener::bind(&config.api_bind_addr).await?;
    tracing::info!("listening on {}", config.api_bind_addr);
    axum::serve(listener, app).await?;

    Ok(())
}
