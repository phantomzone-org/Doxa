use sqlx::PgPool;
use tessera_client::SubpoolId;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub faucet_private_key: String,
    pub sepolia_rpc_url: String,
    pub usdx_contract_addr: String,
    pub subpool_id: SubpoolId,
}
