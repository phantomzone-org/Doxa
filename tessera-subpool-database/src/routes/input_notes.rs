use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};
use serde::Serialize;

use crate::{error::AppError, state::AppState};

#[derive(Serialize)]
pub struct InputNoteEntry {
	pub identifier: String,
	/// hex-encoded F (8 bytes)
	pub asset_id: String,
	/// hex-encoded U256 (32 bytes)
	pub amount: String,
	pub recipient_address: String,
	pub sender_address: String,
	/// hex-encoded memo (≤ 512 bytes)
	pub memo: String,
}

pub async fn get_input_notes_handler(
	State(state): State<AppState>,
	Path(recipient_address): Path<String>,
) -> Result<(StatusCode, Json<Vec<InputNoteEntry>>), AppError> {
	let rows: Vec<(String, Vec<u8>, Vec<u8>, String, String, Vec<u8>)> = sqlx::query_as(
		r#"SELECT identifier, asset_id, amount, recipient_address, sender_address, memo
           FROM input_notes
           WHERE recipient_address = $1 AND status = 'APPROVED'"#,
	)
	.bind(&recipient_address)
	.fetch_all(&state.pool)
	.await
	.map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

	let notes = rows
		.into_iter()
		.map(
			|(identifier, asset_id, amount, recipient_address, sender_address, memo)| {
				InputNoteEntry {
					identifier,
					asset_id: hex::encode(&asset_id),
					amount: hex::encode(&amount),
					recipient_address,
					sender_address,
					memo: hex::encode(&memo),
				}
			},
		)
		.collect();

	Ok((StatusCode::OK, Json(notes)))
}
