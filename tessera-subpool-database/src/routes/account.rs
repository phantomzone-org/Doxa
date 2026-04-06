use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use tessera_client::AssetId;

use crate::{
	convert::account_from_row,
	db::update_account,
	error::AppError,
	state::AppState,
	types::account::AccountRow,
};

/// JSON response body for `GET /account/:private_acc_address`.
///
/// All `BYTEA` columns are returned as lowercase hex strings so the
/// caller does not need to handle raw binary.
#[derive(Serialize)]
pub struct AccountResponse {
	pub private_acc_address: String,
	pub eth_address: String,
	/// 32 hex chars — 16 bytes (2 × u64 LE), `PrivateIdentifier([F; 2])`
	pub private_identifier: String,
	/// 16 hex chars — 8 bytes (1 × u64 LE), `SubpoolId(F)`
	pub subpool_id: String,
	/// 16 hex chars — 8 bytes (1 × u64 LE), `Nonce(F)`
	pub nonce: String,
	/// 80 hex chars — 40 bytes (5 × u64 LE), `CompressedPublicKey` spend-auth; all-zeros if absent
	pub spend_auth: String,
	/// 80 hex chars — 40 bytes (5 × u64 LE), `CompressedPublicKey` consume-auth; all-zeros if
	/// absent
	pub consume_auth: String,
	pub ast: serde_json::Value,
	pub created_at: chrono::DateTime<chrono::Utc>,
	pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<AccountRow> for AccountResponse {
	fn from(row: AccountRow) -> Self {
		AccountResponse {
			private_acc_address: row.private_acc_address,
			eth_address: row.eth_address,
			private_identifier: row.private_identifier,
			subpool_id: hex::encode(&row.subpool_id),
			nonce: hex::encode(&row.nonce),
			spend_auth: hex::encode(&row.spend_auth),
			consume_auth: hex::encode(&row.consume_auth),
			ast: row.ast,
			created_at: row.created_at,
			updated_at: row.updated_at,
		}
	}
}

const PRIVATE_FAUCET_AMOUNT: u64 = 1_000_000_000; // 1000 USDX at 6 decimals

#[derive(Deserialize)]
pub struct PrivateFaucetRequest {
	pub private_acc_address: String,
	/// hex-encoded 8-byte LE u64, e.g. "0100000000000000"
	pub asset_id: String,
}

pub async fn private_faucet_handler(
	State(state): State<AppState>,
	Json(req): Json<PrivateFaucetRequest>,
) -> Result<(StatusCode, Json<AccountResponse>), AppError> {
	// 1. Decode hex asset_id → u64 (LE)
	let asset_id_bytes = hex::decode(req.asset_id.trim_start_matches("0x"))
		.map_err(|_| AppError::InvalidInput("asset_id must be valid hex".into()))?;
	let asset_id_arr: [u8; 8] = asset_id_bytes
		.as_slice()
		.try_into()
		.map_err(|_| AppError::InvalidInput("asset_id must be 8 bytes (16 hex chars)".into()))?;
	let asset_id_u64 = u64::from_le_bytes(asset_id_arr);
	let asset_id = AssetId::from_u64(asset_id_u64)
		.map_err(|e| AppError::InvalidInput(format!("invalid asset_id: {e}")))?;

	// 2. Fetch account row
	let row: Option<AccountRow> =
		sqlx::query_as("SELECT * FROM accounts WHERE private_acc_address = $1")
			.bind(&req.private_acc_address)
			.fetch_optional(&state.pool)
			.await?;
	let row = row.ok_or_else(|| AppError::NotFound("account not found".into()))?;

	// 3. Reconstruct domain model
	let mut acc = account_from_row(&row).map_err(AppError::Internal)?;

	// 4. Get current balance and compute new balance
	let current_balance = acc
		.ast
		.amount_for(asset_id)
		.map(|(_, amount)| amount)
		.unwrap_or(U256::zero());
	let new_balance = current_balance + U256::from(PRIVATE_FAUCET_AMOUNT);

	// 5. Insert or update the asset balance (also updates the Merkle tree)
	acc.ast.insert_or_update_asset(asset_id, new_balance);

	// 6. Write updated account back
	update_account(
		&state.pool,
		&acc,
		row.eth_address.clone(),
		row.private_acc_address.clone(),
	)
	.await
	.map_err(AppError::Internal)?;

	// 7. Fetch and return the updated row
	let updated: AccountRow =
		sqlx::query_as("SELECT * FROM accounts WHERE private_acc_address = $1")
			.bind(&req.private_acc_address)
			.fetch_one(&state.pool)
			.await?;

	Ok((StatusCode::OK, Json(AccountResponse::from(updated))))
}

pub async fn get_account_handler(
	State(state): State<AppState>,
	Path(private_acc_address): Path<String>,
) -> Result<(StatusCode, Json<AccountResponse>), AppError> {
	let row: Option<AccountRow> =
		sqlx::query_as("SELECT * FROM accounts WHERE private_acc_address = $1")
			.bind(&private_acc_address)
			.fetch_optional(&state.pool)
			.await?;

	match row {
		Some(r) => Ok((StatusCode::OK, Json(AccountResponse::from(r)))),
		None => Err(AppError::NotFound("account not found".into())),
	}
}
