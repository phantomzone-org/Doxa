use anyhow::{Context, Result};

pub struct AppConfig {
    /// PostgreSQL connection string. Env: DATABASE_URL (required).
    pub database_url: String,
    /// HTTP bind address. Env: TESSERA_SUBPOOL_API_ADDR (default "0.0.0.0:8080").
    pub api_bind_addr: String,
    /// Max DB connections in pool. Env: DATABASE_MAX_CONNECTIONS (default 10).
    pub db_max_connections: u32,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let database_url =
            std::env::var("DATABASE_URL").context("DATABASE_URL not set")?;

        let api_bind_addr = std::env::var("TESSERA_SUBPOOL_API_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string());

        let db_max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<u32>()
            .context("DATABASE_MAX_CONNECTIONS must be a positive integer")?;

        Ok(Self {
            database_url,
            api_bind_addr,
            db_max_connections,
        })
    }
}
