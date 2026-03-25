use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{PendingTransactionBuilder, Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
};
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::{error::AppError, state::AppState};

/// 0.000000001 ETH in wei
const FAUCET_AMOUNT_WEI: u128 = 1_000_000_000;
/// 10 USDX (6 decimals)
const USDX_MINT_AMOUNT: u64 = 10_000_000;

sol! {
    interface IUSDX {
        function mint(address to, uint256 value) external;
    }
}

#[derive(Deserialize)]
pub struct FaucetRequest {
    pub eth_address: String,
}

#[derive(Serialize)]
pub struct FaucetResponse {
    pub tx_hash: String,
}

pub async fn faucet_handler(
    State(state): State<AppState>,
    Json(req): Json<FaucetRequest>,
) -> Result<(StatusCode, Json<FaucetResponse>), AppError> {
    let to: Address = req
        .eth_address
        .parse()
        .map_err(|_| AppError::InvalidInput("invalid eth_address".into()))?;

    let contract_addr: Address = state
        .usdx_contract_addr
        .parse()
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid USDX_CONTRACT_ADDR")))?;

    // Build signer + provider
    let signer: PrivateKeySigner = state
        .faucet_private_key
        .parse()
        .map_err(|_| AppError::Internal(anyhow::anyhow!("invalid FAUCET_PRIVATE_KEY")))?;
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&state.sepolia_rpc_url)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("provider connect: {e}")))?;

    // Send ETH only if this address hasn't been funded before
    let already_funded: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM faucet_requests WHERE eth_address = $1)",
    )
    .bind(&req.eth_address)
    .fetch_one(&state.pool)
    .await
    .map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

    if !already_funded {
        let eth_tx = TransactionRequest::default()
            .to(to)
            .value(U256::from(FAUCET_AMOUNT_WEI));

        let pending_eth: PendingTransactionBuilder<_> = provider
            .send_transaction(eth_tx)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("eth transfer: {e}")))?;
        let eth_tx_hash = format!("{:#x}", pending_eth.tx_hash());

        sqlx::query("INSERT INTO faucet_requests (eth_address, tx_hash) VALUES ($1, $2)")
            .bind(&req.eth_address)
            .bind(&eth_tx_hash)
            .execute(&state.pool)
            .await
            .map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;
    }

    // Always mint 10 USDX — encode mint(to, value) calldata
    let calldata = IUSDX::mintCall {
        to,
        value: U256::from(USDX_MINT_AMOUNT),
    }
    .abi_encode();

    let mint_tx = TransactionRequest::default()
        .to(contract_addr)
        .input(calldata.into());

    let pending_mint: PendingTransactionBuilder<_> = provider
        .send_transaction(mint_tx)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("mint: {e}")))?;
    let mint_tx_hash = format!("{:#x}", pending_mint.tx_hash());

    Ok((StatusCode::CREATED, Json(FaucetResponse { tx_hash: mint_tx_hash })))
}
