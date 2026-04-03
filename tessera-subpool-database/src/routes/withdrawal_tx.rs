use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::{error::AppError, state::AppState};

#[derive(Deserialize)]
pub struct WithdrawalTxRequest {
	pub priv_acc_address: String,
	/// Ethereum address string, e.g. "0x..."
	pub withdrawal_eth_address: String,
	/// Hex-encoded U256 (32 bytes = 64 hex chars)
	pub amount: String,
	/// Hex-encoded F (8 bytes = 16 hex chars)
	pub asset_id: String,
}

#[derive(Serialize)]
pub struct WithdrawalTxResponse {
	pub id: i64,
}

pub async fn submit_withdrawal_tx_handler(
	State(state): State<AppState>,
	Json(req): Json<WithdrawalTxRequest>,
) -> Result<(StatusCode, Json<WithdrawalTxResponse>), AppError> {
	// ── 1. Verify account exists ────────────────────────────────────────────────
	let account_exists: bool = sqlx::query_scalar(
		"SELECT EXISTS(SELECT 1 FROM accounts WHERE private_acc_address = $1)",
	)
	.bind(&req.priv_acc_address)
	.fetch_one(&state.pool)
	.await
	.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

	if !account_exists {
		return Err(AppError::NotFound(format!(
			"account '{}' not found",
			req.priv_acc_address
		)));
	}

	// ── 2. Decode hex fields ────────────────────────────────────────────────────
	let amount_bytes = hex::decode(&req.amount)
		.map_err(|_| AppError::InvalidInput("invalid amount hex".into()))?;
	if amount_bytes.len() != 32 {
		return Err(AppError::InvalidInput(
			"amount must be 32 bytes (64 hex chars)".into(),
		));
	}

	let asset_id_bytes = hex::decode(&req.asset_id)
		.map_err(|_| AppError::InvalidInput("invalid asset_id hex".into()))?;
	if asset_id_bytes.len() != 8 {
		return Err(AppError::InvalidInput(
			"asset_id must be 8 bytes (16 hex chars)".into(),
		));
	}

	// ── 3. Insert ───────────────────────────────────────────────────────────────
	let row = sqlx::query(
		r#"INSERT INTO withdrawal_tx_requests
		       (priv_acc_address, withdrawal_eth_address, amount, asset_id)
		   VALUES ($1, $2, $3, $4)
		   RETURNING id"#,
	)
	.bind(&req.priv_acc_address)
	.bind(&req.withdrawal_eth_address)
	.bind(&amount_bytes)
	.bind(&asset_id_bytes)
	.fetch_one(&state.pool)
	.await
	.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

	let id: i64 = row
		.try_get("id")
		.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

	Ok((StatusCode::CREATED, Json(WithdrawalTxResponse { id })))
}
