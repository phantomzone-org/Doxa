use axum::{extract::{Path, State}, http::StatusCode, Json};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tessera_client::AssetId;
use tracing::info;

use crate::{
	convert::{account_from_row, bytes_to_u256},
	error::AppError,
	state::AppState,
	types::{account::AccountRow, spend_tx::{InputNoteStatus, SpendTxStatus}},
};

#[derive(Deserialize)]
pub struct NotePayload {
	/// hex string, 32 chars ([F;2] = 16 bytes)
	pub identifier: String,
	/// hex-encoded F (8 bytes = 16 hex chars)
	pub asset_id: String,
	/// hex-encoded U256 (32 bytes = 64 hex chars)
	pub amount: String,
	pub recipient_address: String,
	pub sender_address: String,
	/// hex-encoded memo (≤ 512 bytes = ≤ 1024 hex chars)
	pub memo: String,
}

#[derive(Deserialize)]
pub struct SpendTxRequest {
	pub priv_acc_address: String,
	pub input_notes: Vec<NotePayload>,
	pub output_notes: Vec<NotePayload>,
	pub dinotes: Vec<String>,
	pub donotes: Vec<String>,
	/// hex-encoded spend tx signature
	pub spend_tx_signature: String,
}

#[derive(Serialize)]
pub struct SpendTxResponse {
	pub id: i64,
}

fn u256_add(a: U256, b: U256) -> U256 {
	a.overflowing_add(b).0
}

pub async fn submit_spend_tx_handler(
	State(state): State<AppState>,
	Json(req): Json<SpendTxRequest>,
) -> Result<(StatusCode, Json<SpendTxResponse>), AppError> {
	// ── 0. Fetch and parse account ──────────────────────────────────────────────
	let account_row: Option<AccountRow> =
		sqlx::query_as("SELECT * FROM accounts WHERE private_acc_address = $1")
			.bind(&req.priv_acc_address)
			.fetch_optional(&state.pool)
			.await
			.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;
	let account_row = account_row.ok_or_else(|| {
		AppError::NotFound(format!("account '{}' not found", req.priv_acc_address))
	})?;
	let account =
		account_from_row(&account_row).map_err(|e| AppError::InvalidInput(e.to_string()))?;

	// ── 1. Validate and fetch each input note ──────────────────────────────────
	let mut inote_amounts: Vec<U256> = Vec::with_capacity(req.input_notes.len());

	for note in &req.input_notes {
		if note.identifier.len() != 32 {
			return Err(AppError::InvalidInput(format!(
				"input note identifier '{}' must be 32 hex chars",
				note.identifier
			)));
		}

		let row: Option<(String, Vec<u8>, bool, InputNoteStatus)> = sqlx::query_as(
			"SELECT recipient_address, amount, consume, status FROM input_notes WHERE identifier = $1",
		)
		.bind(&note.identifier)
		.fetch_optional(&state.pool)
		.await
		.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

		let (recipient_address, amount_bytes, consume, status) = row.ok_or_else(|| {
			AppError::InvalidInput(format!("input note '{}' not found", note.identifier))
		})?;

		if recipient_address != req.priv_acc_address {
			return Err(AppError::InvalidInput(format!(
				"input note '{}' recipient does not match priv_acc_address",
				note.identifier
			)));
		}

		if consume {
			return Err(AppError::InvalidInput(format!(
				"input note '{}' is consumed",
				note.identifier
			)));
		}

		if !matches!(status, InputNoteStatus::Approved) || consume {
			return Err(AppError::InvalidInput(format!(
				"input note '{}' is either not approved",
				note.identifier
			)));
		}

		let arr: [u8; 32] = amount_bytes
			.as_slice()
			.try_into()
			.map_err(|_| AppError::InvalidInput("input note amount must be 32 bytes".into()))?;
		inote_amounts.push(bytes_to_u256(&arr));
	}

	// ── 1b. Validate shared asset_id ──────────────────────────────────────────
	let all_asset_ids: Vec<&str> = req
		.input_notes
		.iter()
		.chain(req.output_notes.iter())
		.map(|n| n.asset_id.as_str())
		.collect();

	let asset_id_hex = all_asset_ids
		.first()
		.ok_or_else(|| AppError::InvalidInput("spend tx must have at least one note".into()))?;

	for id in &all_asset_ids {
		if id != asset_id_hex {
			return Err(AppError::InvalidInput(
				"all notes must share the same asset_id".into(),
			));
		}
	}

	// ── 1c. Get account balance for this asset ────────────────────────────────
	let asset_id_bytes_decoded = hex::decode(asset_id_hex)
		.map_err(|_| AppError::InvalidInput("invalid asset_id hex".into()))?;
	let asset_id_arr: [u8; 8] = asset_id_bytes_decoded
		.as_slice()
		.try_into()
		.map_err(|_| AppError::InvalidInput("asset_id must be 8 bytes".into()))?;
	let asset_id = AssetId::from_u64(u64::from_le_bytes(asset_id_arr))
		.map_err(|e| AppError::InvalidInput(e.to_string()))?;
	info!("Spend tx asset id = {:?}", asset_id);
	let account_balance = account
		.ast
		.assets
		.get(&asset_id)
		.map(|(_, amt)| *amt)
		.unwrap_or(U256::zero());

	// ── 2. Validate and decode each output note ────────────────────────────────
	struct DecodedOutput {
		identifier: String,
		asset_id_bytes: Vec<u8>,
		amount_bytes: Vec<u8>,
		amount: U256,
		recipient_address: String,
		sender_address: String,
		memo_bytes: Vec<u8>,
	}

	let mut decoded_outputs: Vec<DecodedOutput> = Vec::with_capacity(req.output_notes.len());

	for note in &req.output_notes {
		if note.sender_address != req.priv_acc_address {
			return Err(AppError::InvalidInput(format!(
				"output note '{}' sender does not match priv_acc_address",
				note.identifier
			)));
		}

		let asset_id_bytes = hex::decode(&note.asset_id).map_err(|_| {
			AppError::InvalidInput(format!(
				"invalid asset_id hex in output note '{}'",
				note.identifier
			))
		})?;
		if asset_id_bytes.len() != 8 {
			return Err(AppError::InvalidInput(format!(
				"output note '{}' asset_id must be 8 bytes",
				note.identifier
			)));
		}

		let amount_bytes = hex::decode(&note.amount).map_err(|_| {
			AppError::InvalidInput(format!(
				"invalid amount hex in output note '{}'",
				note.identifier
			))
		})?;
		if amount_bytes.len() != 32 {
			return Err(AppError::InvalidInput(format!(
				"output note '{}' amount must be 32 bytes",
				note.identifier
			)));
		}

		let arr: [u8; 32] = amount_bytes.as_slice().try_into().unwrap();
		let amount = bytes_to_u256(&arr);

		let memo_bytes = hex::decode(&note.memo).map_err(|_| {
			AppError::InvalidInput(format!(
				"invalid memo hex in output note '{}'",
				note.identifier
			))
		})?;
		if memo_bytes.len() > 512 {
			return Err(AppError::InvalidInput(format!(
				"output note '{}' memo must be at most 512 bytes",
				note.identifier
			)));
		}

		decoded_outputs.push(DecodedOutput {
			identifier: note.identifier.clone(),
			asset_id_bytes,
			amount_bytes,
			amount,
			recipient_address: note.recipient_address.clone(),
			sender_address: note.sender_address.clone(),
			memo_bytes,
		});
	}

	// ── 3. Balance check: account_balance + sum(inotes) == sum(onotes) ──────────
	let total_in = inote_amounts
		.iter()
		.fold(U256::zero(), |a, &v| u256_add(a, v));
	let total_out = decoded_outputs
		.iter()
		.fold(U256::zero(), |acc, d| u256_add(acc, d.amount));

	let available = u256_add(account_balance, total_in);
	// info!(
	// 	"Balance check: total_in={} total_out={} available={}",
	// 	total_in, total_out, available
	// );
	if available < total_out {
		return Err(AppError::InvalidInput(
			"balance mismatch: account_balance + sum(inotes) < sum(onotes)".into(),
		));
	}

	// ── 4. Transactional insert ────────────────────────────────────────────────
	let spend_tx_sig_bytes = hex::decode(&req.spend_tx_signature)
		.map_err(|_| AppError::InvalidInput("invalid spend_tx_signature hex".into()))?;

	let inote_identifiers: Vec<String> = req
		.input_notes
		.iter()
		.map(|n| n.identifier.clone())
		.collect();
	let onote_identifiers: Vec<String> = req
		.output_notes
		.iter()
		.map(|n| n.identifier.clone())
		.collect();

	let mut tx = state
		.pool
		.begin()
		.await
		.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

	let row = sqlx::query(
        r#"INSERT INTO spend_tx_requests
               (priv_acc_address, inote_identifiers, onote_identifiers, dinotes, donotes, spend_tx_signature)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING id"#,
    )
    .bind(&req.priv_acc_address)
    .bind(&inote_identifiers)
    .bind(&onote_identifiers)
    .bind(&req.dinotes)
    .bind(&req.donotes)
    .bind(&spend_tx_sig_bytes)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

	let id: i64 = row
		.try_get("id")
		.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

	for out in &decoded_outputs {
		sqlx::query(
			r#"INSERT INTO output_notes
                   (identifier, asset_id, amount, recipient_address, sender_address, memo)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
		)
		.bind(&out.identifier)
		.bind(&out.asset_id_bytes)
		.bind(&out.amount_bytes)
		.bind(&out.recipient_address)
		.bind(&out.sender_address)
		.bind(&out.memo_bytes)
		.execute(&mut *tx)
		.await
		.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;
	}

	tx.commit()
		.await
		.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

	Ok((
		StatusCode::CREATED,
		Json(SpendTxResponse {
			id,
		}),
	))
}

#[derive(Serialize)]
pub struct SpendTxStatusResponse {
	pub id: i64,
	pub status: SpendTxStatus,
	pub rejection_reason: Option<String>,
}

pub async fn get_spend_tx_status_handler(
	State(state): State<AppState>,
	Path(id): Path<i64>,
) -> Result<(StatusCode, Json<SpendTxStatusResponse>), AppError> {
	let row: Option<(i64, SpendTxStatus, Option<String>)> = sqlx::query_as(
		"SELECT id, status, rejection_reason FROM spend_tx_requests WHERE id = $1",
	)
	.bind(id)
	.fetch_optional(&state.pool)
	.await?;

	match row {
		None => Err(AppError::NotFound(format!("spend tx {id} not found"))),
		Some((id, status, rejection_reason)) => Ok((
			StatusCode::OK,
			Json(SpendTxStatusResponse { id, status, rejection_reason }),
		)),
	}
}
