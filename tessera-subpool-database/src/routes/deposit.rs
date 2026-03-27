use axum::{extract::{Path, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::{error::AppError, state::AppState, types::deposit::DepositTxStatus};

#[derive(Deserialize)]
pub struct DepositRequest {
	pub recipient_acc_address: String,
	pub eth_address: String,
	/// hex-encoded [F;2] (16 bytes)
	pub deposit_note_identifier: String,
	/// hex-encoded U256 (32 bytes)
	pub deposit_amount: String,
	/// hex-encoded F (8 bytes)
	pub asset_id: String,
	/// hex-encoded RLP-encoded signed ETH tx
	pub signed_public_tx: String,
}

#[derive(Serialize)]
pub struct DepositResponse {
	pub id: i64,
}

#[derive(Serialize)]
pub struct DepositStatusResponse {
	pub id: i64,
	pub status: DepositTxStatus,
	pub deposit_tx_hash: Option<String>,
}

pub async fn get_deposit_status_handler(
	State(state): State<AppState>,
	Path(id): Path<i64>,
) -> Result<(StatusCode, Json<DepositStatusResponse>), AppError> {
	let row: Option<(i64, DepositTxStatus, Option<String>)> = sqlx::query_as(
		"SELECT id, status, deposit_tx_hash FROM deposit_tx_requests WHERE id = $1",
	)
	.bind(id)
	.fetch_optional(&state.pool)
	.await?;

	match row {
		None => Err(AppError::NotFound(format!("deposit {id} not found"))),
		Some((id, status, deposit_tx_hash)) => Ok((
			StatusCode::OK,
			Json(DepositStatusResponse { id, status, deposit_tx_hash }),
		)),
	}
}

pub async fn submit_deposit_handler(
	State(state): State<AppState>,
	Json(req): Json<DepositRequest>,
) -> Result<(StatusCode, Json<DepositResponse>), AppError> {
	let note_id_bytes = hex::decode(&req.deposit_note_identifier)
		.map_err(|_| AppError::InvalidInput("invalid deposit_note_identifier hex".into()))?;
	let amount_bytes = hex::decode(&req.deposit_amount)
		.map_err(|_| AppError::InvalidInput("invalid deposit_amount hex".into()))?;
	let asset_id_bytes = hex::decode(&req.asset_id)
		.map_err(|_| AppError::InvalidInput("invalid asset_id hex".into()))?;
	let signed_tx_bytes = hex::decode(&req.signed_public_tx)
		.map_err(|_| AppError::InvalidInput("invalid signed_public_tx hex".into()))?;

	let exists: bool = sqlx::query_scalar(
		"SELECT EXISTS(SELECT 1 FROM deposit_tx_requests WHERE deposit_note_identifier = $1)",
	)
	.bind(&note_id_bytes)
	.fetch_one(&state.pool)
	.await
	.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

	if exists {
		return Err(AppError::AlreadyExists(
			"deposit request with this note identifier already exists".into(),
		));
	}

	let row = sqlx::query(
		r#"INSERT INTO deposit_tx_requests
               (recipient_acc_address, eth_address, deposit_note_identifier,
                deposit_amount, asset_id, signed_public_tx)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id"#,
	)
	.bind(&req.recipient_acc_address)
	.bind(&req.eth_address)
	.bind(&note_id_bytes)
	.bind(&amount_bytes)
	.bind(&asset_id_bytes)
	.bind(&signed_tx_bytes)
	.fetch_one(&state.pool)
	.await
	.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

	let id: i64 = row
		.try_get("id")
		.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

	Ok((
		StatusCode::CREATED,
		Json(DepositResponse {
			id,
		}),
	))
}
