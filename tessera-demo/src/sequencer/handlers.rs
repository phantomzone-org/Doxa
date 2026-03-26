use std::time::Instant;

use alloy::primitives::B256;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tessera_client::NOTE_BATCH;
use tessera_server::{contract::ITesseraRollupV2, sequencer::BatchBuilder};
use tracing::info;

use axum::extract::Path;

use super::helpers::{parse_hex_bytes, parse_hex_bytes32};
use super::state::{AppState, ForwardedNote};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct DepositValidationRequest {
	note_commitment: String,
}

#[derive(Serialize)]
pub(crate) struct DepositValidationResponse {
	status: String,
	note_commitment: String,
	pending_deposits: usize,
}

#[derive(Deserialize)]
pub(crate) struct TransactionRequest {
	tx_id: Option<String>,
	input_account_leaf: String,
	output_account_leaf: String,
	input_notes: Vec<String>,
	output_notes: Vec<String>,
	tx_proof: String,
}

#[derive(Serialize)]
pub(crate) struct TransactionResponse {
	status: String,
	tx_id: String,
	batch_slots_used: usize,
}

#[derive(Serialize)]
pub(crate) struct StatusResponse {
	confirmed_root: String,
	tx_batch_slots: usize,
	pending_deposits: usize,
	confirmed_roots_count: usize,
}

#[derive(Serialize)]
pub(crate) struct ConfigResponse {
	contract_address: String,
	token_address: String,
	operator_address: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub(crate) async fn handle_deposit(
	State((state, provider)): State<AppState>,
	Json(req): Json<DepositValidationRequest>,
) -> Result<Json<DepositValidationResponse>, (StatusCode, String)> {
	let nc_bytes =
		parse_hex_bytes32(&req.note_commitment).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
	let nc = B256::from(nc_bytes);

	// Verify the deposit exists on-chain and is Pending.
	let rollup_addr = state.lock().await.rollup_addr;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider.as_ref());
	let deposit_info = rollup.getDeposit(nc).call().await.map_err(|e| {
		(
			StatusCode::INTERNAL_SERVER_ERROR,
			format!("failed to query deposit: {e}"),
		)
	})?;

	// Status: 0=None, 1=Pending, 2=Validated, 3=Withdrawn.
	let status: u8 = deposit_info.status.into();
	if status != 1 {
		return Err((
			StatusCode::BAD_REQUEST,
			format!(
				"deposit is not Pending (status={status}), \
				 did you call depositAndRegister on-chain first?"
			),
		));
	}

	let pending_deposits = {
		let mut st = state.lock().await;
		st.deposit_queue.push(nc);
		if st.deposit_batch_pending_since.is_none() {
			st.deposit_batch_pending_since = Some(Instant::now());
		}
		st.deposit_queue.len()
	};

	info!(note_commitment = %nc, "deposit validation request queued");

	Ok(Json(DepositValidationResponse {
		status: "queued".to_string(),
		note_commitment: format!("{nc}"),
		pending_deposits,
	}))
}

pub(crate) async fn handle_transaction(
	State((state, _provider)): State<AppState>,
	Json(req): Json<TransactionRequest>,
) -> Result<Json<TransactionResponse>, (StatusCode, String)> {
	let input_account_leaf =
		parse_hex_bytes32(&req.input_account_leaf).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
	let output_account_leaf =
		parse_hex_bytes32(&req.output_account_leaf).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

	let input_notes: Vec<[u8; 32]> = req
		.input_notes
		.iter()
		.map(|s| parse_hex_bytes32(s))
		.collect::<Result<_, _>>()
		.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

	let output_notes: Vec<[u8; 32]> = req
		.output_notes
		.iter()
		.map(|s| parse_hex_bytes32(s))
		.collect::<Result<_, _>>()
		.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

	let tx_proof = parse_hex_bytes(&req.tx_proof).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
	let tx_id = req.tx_id.unwrap_or_else(|| "anonymous".to_string());

	let nc: [[u8; 32]; NOTE_BATCH] = {
		let mut arr = [[0u8; 32]; NOTE_BATCH];
		for (i, note) in output_notes.iter().enumerate().take(NOTE_BATCH) {
			arr[i] = *note;
		}
		arr
	};
	let nn: [[u8; 32]; NOTE_BATCH] = {
		let mut arr = [[0u8; 32]; NOTE_BATCH];
		for (i, note) in input_notes.iter().enumerate().take(NOTE_BATCH) {
			arr[i] = *note;
		}
		arr
	};

	let slots_used = {
		let mut st = state.lock().await;

		if st
			.tx_batch_builder
			.as_ref()
			.is_some_and(|b| b.contains_an(&input_account_leaf))
		{
			return Err((
				StatusCode::CONFLICT,
				"AN leaf already in current batch".to_string(),
			));
		}
		for note in &input_notes {
			if st
				.tx_batch_builder
				.as_ref()
				.is_some_and(|b| b.contains_nn(note))
			{
				return Err((
					StatusCode::CONFLICT,
					"NN leaf already in current batch".to_string(),
				));
			}
		}

		if st.tx_batch_builder.is_none() {
			st.tx_batch_builder = Some(BatchBuilder::new());
			st.tx_batch_pending_since = Some(Instant::now());
		}

		st.tx_batch_builder
			.as_mut()
			.unwrap()
			.add_private_tx(tx_proof, output_account_leaf, input_account_leaf, nc, nn)
			.map_err(|e| {
				(
					StatusCode::INTERNAL_SERVER_ERROR,
					format!("batch error: {e}"),
				)
			})?;

		st.tx_batch_builder.as_ref().unwrap().len()
	};

	info!(tx_id = %tx_id, slots_used, "transaction queued");

	Ok(Json(TransactionResponse {
		status: "queued".to_string(),
		tx_id,
		batch_slots_used: slots_used,
	}))
}

pub(crate) async fn handle_status(State((state, _)): State<AppState>) -> Json<StatusResponse> {
	let st = state.lock().await;
	Json(StatusResponse {
		confirmed_root: format!("{}", st.confirmed_root),
		tx_batch_slots: st.tx_batch_builder.as_ref().map_or(0, |b| b.len()),
		pending_deposits: st.deposit_queue.len(),
		confirmed_roots_count: st.confirmed_root_history.len(),
	})
}

pub(crate) async fn handle_config(State((state, _)): State<AppState>) -> Json<ConfigResponse> {
	let st = state.lock().await;
	Json(ConfigResponse {
		contract_address: format!("{}", st.rollup_addr),
		token_address: format!("{}", st.token_addr),
		operator_address: format!("{}", st.operator),
	})
}

// ---------------------------------------------------------------------------
// Cross-subpool note forwarding
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct ForwardNoteRequest {
	pub target_subpool_id: u64,
	#[serde(flatten)]
	pub note: ForwardedNote,
}

#[derive(Serialize)]
pub(crate) struct ForwardNoteResponse {
	status: String,
	target_subpool_id: u64,
	queue_size: usize,
}

pub(crate) async fn handle_forward_note(
	State((state, _)): State<AppState>,
	Json(req): Json<ForwardNoteRequest>,
) -> Result<Json<ForwardNoteResponse>, (StatusCode, String)> {
	let mut st = state.lock().await;
	let queue = st.note_pool.entry(req.target_subpool_id).or_default();
	queue.push(req.note);
	let queue_size = queue.len();

	info!(
		target_subpool = req.target_subpool_id,
		queue_size,
		"forwarded note queued"
	);

	Ok(Json(ForwardNoteResponse {
		status: "queued".to_string(),
		target_subpool_id: req.target_subpool_id,
		queue_size,
	}))
}

pub(crate) async fn handle_pending_notes(
	State((state, _)): State<AppState>,
	Path(subpool_id): Path<u64>,
) -> Json<Vec<ForwardedNote>> {
	let mut st = state.lock().await;
	let notes = st.note_pool.remove(&subpool_id).unwrap_or_default();

	if !notes.is_empty() {
		info!(subpool_id, count = notes.len(), "drained pending notes");
	}

	Json(notes)
}

// ---------------------------------------------------------------------------
// NCT position lookup
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(crate) struct NotePositionResponse {
	commitment: String,
	position: u64,
}

pub(crate) async fn handle_note_position(
	State((state, _)): State<AppState>,
	Path(commitment_hex): Path<String>,
) -> Result<Json<NotePositionResponse>, (StatusCode, String)> {
	let st = state.lock().await;
	let position = st.note_positions.get(&commitment_hex).copied().ok_or_else(|| {
		(
			StatusCode::NOT_FOUND,
			format!("note commitment '{commitment_hex}' not found in NCT"),
		)
	})?;

	Ok(Json(NotePositionResponse {
		commitment: commitment_hex,
		position,
	}))
}
