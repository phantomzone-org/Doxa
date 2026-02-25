use std::sync::Arc;

use alloy::primitives::B256;
use axum::{extract::State, routing::post, Json, Router};
use plonky2::{
	plonk::{
		circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData},
		proof::ProofWithPublicInputs,
	},
	util::serialization::DefaultGateSerializer,
};
use serde::{Deserialize, Serialize};
use tessera_trees::{ConfigNative, D, F};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::{contract::GOLDILOCKS_PRIME, sequencer::NotesCommitmentRequest};

/// Verifies a plonky2 leaf proof against the aggregator's leaf circuit.
///
/// Loaded from aggregator artifacts at startup by reading `leaf_common.bin`
/// and `leaf_verifier.bin`. When not configured, any non-empty proof bytes
/// are accepted and cryptographic validation is deferred to the prover.
pub(super) struct LeafProofVerifier {
	verifier_data: VerifierCircuitData<F, ConfigNative, D>,
}

impl LeafProofVerifier {
	/// Load from an aggregator artifacts directory.
	///
	/// Reads only `leaf_common.bin` and `leaf_verifier.bin` — the level
	/// circuits are not loaded, keeping startup cost minimal.
	pub(super) fn from_artifacts(path: &std::path::Path) -> anyhow::Result<Self> {
		let gate_ser = DefaultGateSerializer;

		let common_bytes = std::fs::read(path.join("leaf_common.bin"))
			.map_err(|e| anyhow::anyhow!("failed to read leaf_common.bin from {:?}: {e}", path))?;
		let common = CommonCircuitData::<F, D>::from_bytes(&common_bytes, &gate_ser)
			.map_err(|e| anyhow::anyhow!("failed to deserialize leaf_common.bin: {e:?}"))?;

		let verifier_bytes = std::fs::read(path.join("leaf_verifier.bin")).map_err(|e| {
			anyhow::anyhow!("failed to read leaf_verifier.bin from {:?}: {e}", path)
		})?;
		let verifier_only = VerifierOnlyCircuitData::<ConfigNative, D>::from_bytes(&verifier_bytes)
			.map_err(|e| anyhow::anyhow!("failed to deserialize leaf_verifier.bin: {e:?}"))?;

		Ok(Self {
			verifier_data: VerifierCircuitData {
				verifier_only,
				common,
			},
		})
	}

	/// Deserialize and verify `proof_bytes` against the leaf circuit.
	fn verify_bytes(&self, proof_bytes: &[u8]) -> anyhow::Result<()> {
		let proof = ProofWithPublicInputs::<F, ConfigNative, D>::from_bytes(
			proof_bytes.to_vec(),
			&self.verifier_data.common,
		)
		.map_err(|e| anyhow::anyhow!("leaf proof deserialization failed: {e:?}"))?;
		self.verifier_data
			.verify(proof)
			.map_err(|e| anyhow::anyhow!("leaf proof verification failed: {e:?}"))
	}
}

#[derive(Clone)]
pub(super) struct ApiState {
	pub(super) notes_commitment_tx: mpsc::Sender<NotesCommitmentRequest>,
	pub(super) notes_nullifier_tx: mpsc::Sender<[u8; 32]>,
	pub(super) accounts_commitment_tx: mpsc::Sender<[u8; 32]>,
	pub(super) accounts_nullifier_tx: mpsc::Sender<[u8; 32]>,
	/// When `Some`, `/private-tx` uses the optimistic two-phase register path.
	/// When `None`, falls back to the per-tree fan-out (deposit-only) path.
	pub(super) private_tx_tx: Option<mpsc::Sender<super::PrivateTxRequest>>,
	/// 4-PI verifier for `/consume-request`. `None` = accept any non-empty proof.
	pub(super) consume_proof_verifier: Option<Arc<LeafProofVerifier>>,
	/// 72-PI verifier for `/private-tx`. `None` = accept any non-empty proof.
	pub(super) tx_proof_verifier: Option<Arc<LeafProofVerifier>>,
	/// 8-PI verifier for `/accounts/commitment`. `None` = accept bare leaf without proof.
	pub(super) account_proof_verifier: Option<Arc<LeafProofVerifier>>,
}

#[derive(Debug, Deserialize)]
struct ConsumeRequestBody {
	note_commitment: String,
	input_proof: String,
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
struct AccountRegisterBody {
	leaf: String,
	input_proof: String,
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
		has_input_proof = !body.input_proof.is_empty(),
		"received deposit request"
	);
	let proof = match parse_input_proof_hex(&body.input_proof) {
		Ok(v) => v,
		Err(_) => {
			warn!("rejecting deposit: invalid input proof hex");
			return Ok(Json(ConsumeRequestResponse {
				accepted: false,
				invalid_proof_tx: Some(InvalidProofTx {
					tx_id: None,
					reason: "input proof is not valid hex".to_string(),
				}),
			}));
		},
	};
	if let Err(e) = verify_associated_tx_proof(&proof, state.consume_proof_verifier.as_deref()) {
		warn!(
			reason = %e,
			"rejecting deposit: proof verification failed"
		);
		return Ok(Json(ConsumeRequestResponse {
			accepted: false,
			invalid_proof_tx: Some(InvalidProofTx {
				tx_id: None,
				reason: e.to_string(),
			}),
		}));
	}
	info!(proof_len = proof.len(), "deposit proof verified");
	let note =
		parse_note_hex(&body.note_commitment).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	state
		.notes_commitment_tx
		.send(NotesCommitmentRequest {
			note,
		})
		.await
		.map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
	info!(note = ?B256::from(note), "accepted deposit");
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
	if let Err(e) = verify_associated_tx_proof(&tx_proof, state.tx_proof_verifier.as_deref()) {
		warn!(
			tx_id = body.tx_id.as_deref().unwrap_or("unknown"),
			reason = %e,
			"rejecting private tx: proof verification failed"
		);
		return Ok(Json(ConsumeRequestResponse {
			accepted: false,
			invalid_proof_tx: Some(InvalidProofTx {
				tx_id: body.tx_id,
				reason: e.to_string(),
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
	let input_account_leaf = parse_note_hex(&body.input_account_commitment)
		.map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	let output_account_leaf = parse_note_hex(&body.output_account_commitment)
		.map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	let input_notes_count = input_notes.len();
	let output_notes_count = output_notes.len();

	state
		.private_tx_tx
		.as_ref()
		.ok_or(axum::http::StatusCode::SERVICE_UNAVAILABLE)?
		.send(super::PrivateTxRequest {
			tx_id: body.tx_id,
			input_notes,
			output_notes,
			input_account_leaf,
			output_account_leaf,
			tx_proof,
		})
		.await
		.map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
	info!(
		enqueued_notes_nullifier = input_notes_count,
		enqueued_notes_commitment = output_notes_count,
		"accepted private tx via optimistic register path"
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
	Json(body): Json<AccountRegisterBody>,
) -> Result<Json<ConsumeRequestResponse>, axum::http::StatusCode> {
	let proof = match parse_input_proof_hex(&body.input_proof) {
		Ok(v) => v,
		Err(_) => {
			warn!("rejecting account registration: invalid input proof hex");
			return Ok(Json(ConsumeRequestResponse {
				accepted: false,
				invalid_proof_tx: Some(InvalidProofTx {
					tx_id: None,
					reason: "input proof is not valid hex".to_string(),
				}),
			}));
		},
	};
	if let Err(e) = verify_associated_tx_proof(&proof, state.account_proof_verifier.as_deref()) {
		warn!(
			reason = %e,
			"rejecting account registration: proof verification failed"
		);
		return Ok(Json(ConsumeRequestResponse {
			accepted: false,
			invalid_proof_tx: Some(InvalidProofTx {
				tx_id: None,
				reason: e.to_string(),
			}),
		}));
	}
	info!(
		proof_len = proof.len(),
		"account registration proof verified"
	);
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
	// Validate every 64-bit limb is within the Goldilocks field so
	// bytes32_to_hash never silently wraps an out-of-range commitment.
	let bytes = b.as_slice();
	for i in 0..4usize {
		let limb = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
		anyhow::ensure!(
			limb < GOLDILOCKS_PRIME,
			"note commitment limb {i} is out of Goldilocks field range"
		);
	}
	Ok(b.into())
}

fn parse_input_proof_hex(s: &str) -> anyhow::Result<Vec<u8>> {
	let s = s.strip_prefix("0x").unwrap_or(s);
	let bytes = hex::decode(s)?;
	anyhow::ensure!(!bytes.is_empty(), "input proof cannot be empty");
	Ok(bytes)
}

/// Verify an associated transaction proof.
///
/// When `verifier` is `Some`, the proof bytes are deserialized and verified
/// cryptographically against the leaf circuit. When `None`, any non-empty
/// bytes are accepted and validation is deferred to the prover.
fn verify_associated_tx_proof(
	proof: &[u8],
	verifier: Option<&LeafProofVerifier>,
) -> anyhow::Result<()> {
	if proof.is_empty() {
		anyhow::bail!("associated input proof cannot be empty");
	}
	if let Some(v) = verifier {
		v.verify_bytes(proof)?;
	}
	Ok(())
}
