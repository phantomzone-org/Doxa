use alloy::primitives::B256;
use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[derive(Clone)]
pub(super) struct ApiState {
	pub(super) notes_commitment_tx: mpsc::Sender<[u8; 32]>,
	pub(super) notes_nullifier_tx: mpsc::Sender<[u8; 32]>,
	pub(super) accounts_commitment_tx: mpsc::Sender<[u8; 32]>,
	pub(super) accounts_nullifier_tx: mpsc::Sender<[u8; 32]>,
}

#[derive(Debug, Deserialize)]
struct ConsumeRequestBody {
	note_commitment: String,
	input_proof: Option<String>,
}

#[derive(Debug, Serialize)]
struct ConsumeRequestResponse {
	accepted: bool,
	invalid_proof_tx: Option<InvalidProofTx>,
}

#[derive(Debug, Serialize)]
struct InvalidProofTx {
	tx_id: Option<String>,
	reason: String,
}

#[derive(Debug, Deserialize)]
struct LeafBody {
	leaf: String,
}

#[derive(Debug, Deserialize)]
struct PrivateTxBody {
	input_notes: Vec<String>,
	output_notes: Vec<String>,
	input_account_commitment: String,
	output_account_commitment: String,
	tx_proof: String,
	tx_id: Option<String>,
}

pub(super) fn build_router(state: ApiState) -> Router {
	Router::new()
		.route("/consume-request", post(consume_request_handler))
		.route("/notes/commitment", post(consume_request_handler))
		.route("/private-tx", post(private_tx_notes_handler))
		.route("/private-tx/notes", post(private_tx_notes_handler))
		.route("/notes/nullifier", post(notes_nullifier_handler))
		.route("/accounts/commitment", post(accounts_commitment_handler))
		.route("/accounts/nullifier", post(accounts_nullifier_handler))
		.with_state(state)
}

async fn consume_request_handler(
	State(state): State<ApiState>,
	Json(body): Json<ConsumeRequestBody>,
) -> Result<Json<ConsumeRequestResponse>, axum::http::StatusCode> {
	debug!(
		has_input_proof = body.input_proof.is_some(),
		"received notes commitment request"
	);
	if let Some(p) = &body.input_proof {
		let proof = match parse_input_proof_hex(p) {
			Ok(v) => v,
			Err(_) => {
				warn!("rejecting notes commitment request: invalid input proof hex");
				return Ok(Json(ConsumeRequestResponse {
					accepted: false,
					invalid_proof_tx: Some(InvalidProofTx {
						tx_id: None,
						reason: "input proof is not valid hex".to_string(),
					}),
				}));
			},
		};
		if let Err(reason) = verify_associated_tx_proof(&proof) {
			warn!(reason, "rejecting notes commitment request: proof verification failed");
			return Ok(Json(ConsumeRequestResponse {
				accepted: false,
				invalid_proof_tx: Some(InvalidProofTx {
					tx_id: None,
					reason: reason.to_string(),
				}),
			}));
		}
		info!(proof_len = proof.len(), "notes commitment proof verified");
	}
	let note = parse_note_hex(&body.note_commitment).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	state
		.notes_commitment_tx
		.send(note)
		.await
		.map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
	info!(note = ?B256::from(note), "accepted notes commitment leaf");
	Ok(Json(ConsumeRequestResponse {
		accepted: true,
		invalid_proof_tx: None,
	}))
}

async fn private_tx_notes_handler(
	State(state): State<ApiState>,
	Json(body): Json<PrivateTxBody>,
) -> Result<Json<ConsumeRequestResponse>, axum::http::StatusCode> {
	debug!(
		tx_id = body.tx_id.as_deref().unwrap_or("unknown"),
		input_notes = body.input_notes.len(),
		output_notes = body.output_notes.len(),
		"received private tx request"
	);
	let tx_proof = match parse_input_proof_hex(&body.tx_proof) {
		Ok(v) => v,
		Err(_) => {
			warn!(
				tx_id = body.tx_id.as_deref().unwrap_or("unknown"),
				"rejecting private tx: invalid tx proof hex"
			);
			return Ok(Json(ConsumeRequestResponse {
				accepted: false,
				invalid_proof_tx: Some(InvalidProofTx {
					tx_id: body.tx_id,
					reason: "tx proof is not valid hex".to_string(),
				}),
			}));
		},
	};
	if let Err(reason) = verify_associated_tx_proof(&tx_proof) {
		warn!(
			tx_id = body.tx_id.as_deref().unwrap_or("unknown"),
			reason,
			"rejecting private tx: proof verification failed"
		);
		return Ok(Json(ConsumeRequestResponse {
			accepted: false,
			invalid_proof_tx: Some(InvalidProofTx {
				tx_id: body.tx_id,
				reason: reason.to_string(),
			}),
		}));
	}
	info!(
		tx_id = body.tx_id.as_deref().unwrap_or("unknown"),
		proof_len = tx_proof.len(),
		"private tx proof verified"
	);
	if body.input_notes.is_empty() && body.output_notes.is_empty() {
		return Err(axum::http::StatusCode::BAD_REQUEST);
	}

	let input_notes: Vec<[u8; 32]> = body
		.input_notes
		.into_iter()
		.map(|n| parse_note_hex(&n))
		.collect::<Result<Vec<_>, _>>()
		.map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	let output_notes: Vec<[u8; 32]> = body
		.output_notes
		.into_iter()
		.map(|n| parse_note_hex(&n))
		.collect::<Result<Vec<_>, _>>()
		.map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	let input_account_leaf =
		parse_note_hex(&body.input_account_commitment).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	let output_account_leaf = parse_note_hex(&body.output_account_commitment)
		.map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	let input_notes_count = input_notes.len();
	let output_notes_count = output_notes.len();

	for leaf in input_notes {
		state
			.notes_nullifier_tx
			.send(leaf)
			.await
			.map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
	}
	for leaf in output_notes {
		state
			.notes_commitment_tx
			.send(leaf)
			.await
			.map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
	}
	state
		.accounts_nullifier_tx
		.send(input_account_leaf)
		.await
		.map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
	state
		.accounts_commitment_tx
		.send(output_account_leaf)
		.await
		.map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
	info!(
		tx_id = body.tx_id.as_deref().unwrap_or("unknown"),
		enqueued_notes_nullifier = input_notes_count,
		enqueued_notes_commitment = output_notes_count,
		enqueued_accounts_nullifier = 1,
		enqueued_accounts_commitment = 1,
		"accepted private tx leaves into sequencer pools"
	);

	Ok(Json(ConsumeRequestResponse {
		accepted: true,
		invalid_proof_tx: None,
	}))
}

async fn notes_nullifier_handler(
	State(state): State<ApiState>,
	Json(body): Json<LeafBody>,
) -> Result<Json<ConsumeRequestResponse>, axum::http::StatusCode> {
	let leaf = parse_note_hex(&body.leaf).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	state
		.notes_nullifier_tx
		.send(leaf)
		.await
		.map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
	info!(leaf = ?B256::from(leaf), "accepted notes nullifier leaf");
	Ok(Json(ConsumeRequestResponse {
		accepted: true,
		invalid_proof_tx: None,
	}))
}

async fn accounts_commitment_handler(
	State(state): State<ApiState>,
	Json(body): Json<LeafBody>,
) -> Result<Json<ConsumeRequestResponse>, axum::http::StatusCode> {
	let leaf = parse_note_hex(&body.leaf).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	state
		.accounts_commitment_tx
		.send(leaf)
		.await
		.map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
	info!(leaf = ?B256::from(leaf), "accepted accounts commitment leaf");
	Ok(Json(ConsumeRequestResponse {
		accepted: true,
		invalid_proof_tx: None,
	}))
}

async fn accounts_nullifier_handler(
	State(state): State<ApiState>,
	Json(body): Json<LeafBody>,
) -> Result<Json<ConsumeRequestResponse>, axum::http::StatusCode> {
	let leaf = parse_note_hex(&body.leaf).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	state
		.accounts_nullifier_tx
		.send(leaf)
		.await
		.map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
	info!(leaf = ?B256::from(leaf), "accepted accounts nullifier leaf");
	Ok(Json(ConsumeRequestResponse {
		accepted: true,
		invalid_proof_tx: None,
	}))
}

fn parse_note_hex(s: &str) -> anyhow::Result<[u8; 32]> {
	let b = s.parse::<B256>()?;
	Ok(b.into())
}

fn parse_input_proof_hex(s: &str) -> anyhow::Result<Vec<u8>> {
	let s = s.strip_prefix("0x").unwrap_or(s);
	let bytes = hex::decode(s)?;
	anyhow::ensure!(!bytes.is_empty(), "input proof cannot be empty");
	Ok(bytes)
}

fn verify_associated_tx_proof(proof: &[u8]) -> Result<(), &'static str> {
	if proof.is_empty() {
		return Err("tx proof is empty");
	}
	if proof[0] != 0x01 {
		return Err("tx proof verification failed");
	}
	Ok(())
}
