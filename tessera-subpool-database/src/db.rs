use anyhow::Result;
use sqlx::postgres::PgPoolOptions;

pub async fn create_pool(database_url: &str, max_connections: u32) -> Result<sqlx::PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)
        .await?)
}
