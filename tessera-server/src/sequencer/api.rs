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

/// Verifies a plonky2 proof against a circuit's verifier data.
///
/// Used for both consume proofs (loaded from consume artifacts) and
/// private-tx proofs (loaded from aggregator artifacts).
/// When not configured, any non-empty proof bytes are accepted and
/// cryptographic validation is deferred to the prover.
pub(super) struct LeafProofVerifier {
	verifier_data: VerifierCircuitData<F, ConfigNative, D>,
}

impl LeafProofVerifier {
	/// Load from an artifacts directory using `leaf_common.bin` + `leaf_verifier.bin`.
	pub(super) fn from_artifacts(path: &std::path::Path) -> anyhow::Result<Self> {
		Self::from_files(path, "leaf_common.bin", "leaf_verifier.bin")
	}

	/// Build the inner PrivTx circuit verifier by compiling the circuit from scratch.
	///
	/// The inner circuit uses custom gates (ECGFp5 `DoubleAdd4x`) that cannot be
	/// serialized with `DefaultGateSerializer`, so we reconstruct the circuit at
	/// startup instead of loading from files. Only the circuit compilation runs
	/// (no proving), so this is fast (~1s).
	///
	/// This verifies raw client-submitted PrivTx proofs at the API layer,
	/// before they reach the aggregator.
	pub(super) fn from_inner_circuit() -> Self {
		let (circuit, _dummy_proof) = tessera_client::build_circuit_and_dummy_proof();
		Self {
			verifier_data: VerifierCircuitData {
				verifier_only: circuit.verifier_only,
				common: circuit.common,
			},
		}
	}

	fn from_files(
		path: &std::path::Path,
		common_name: &str,
		verifier_name: &str,
	) -> anyhow::Result<Self> {
		let gate_ser = DefaultGateSerializer;

		let common_bytes = std::fs::read(path.join(common_name))
			.map_err(|e| anyhow::anyhow!("failed to read {common_name} from {:?}: {e}", path))?;
		let common = CommonCircuitData::<F, D>::from_bytes(&common_bytes, &gate_ser)
			.map_err(|e| anyhow::anyhow!("failed to deserialize {common_name}: {e:?}"))?;

		let verifier_bytes = std::fs::read(path.join(verifier_name))
			.map_err(|e| anyhow::anyhow!("failed to read {verifier_name} from {:?}: {e}", path))?;
		let verifier_only = VerifierOnlyCircuitData::<ConfigNative, D>::from_bytes(&verifier_bytes)
			.map_err(|e| anyhow::anyhow!("failed to deserialize {verifier_name}: {e:?}"))?;

		Ok(Self {
			verifier_data: VerifierCircuitData {
				verifier_only,
				common,
			},
		})
	}

	/// Deserialize and verify `proof_bytes` against the circuit.
	fn verify_bytes(&self, proof_bytes: &[u8]) -> anyhow::Result<()> {
		self.verify_and_extract_pis(proof_bytes)?;
		Ok(())
	}

	/// Deserialize, verify, and return the public inputs from a proof.
	fn verify_and_extract_pis(&self, proof_bytes: &[u8]) -> anyhow::Result<Vec<F>> {
		let proof = ProofWithPublicInputs::<F, ConfigNative, D>::from_bytes(
			proof_bytes.to_vec(),
			&self.verifier_data.common,
		)
		.map_err(|e| anyhow::anyhow!("proof deserialization failed: {e:?}"))?;
		let pis = proof.public_inputs.clone();
		self.verifier_data
			.verify(proof)
			.map_err(|e| anyhow::anyhow!("proof verification failed: {e:?}"))?;
		Ok(pis)
	}
}

#[derive(Clone)]
pub(super) struct ApiState {
	pub(super) notes_commitment_tx: mpsc::Sender<NotesCommitmentRequest>,
	/// When `Some`, `/private-tx` uses the optimistic two-phase register path.
	/// When `None`, falls back to the per-tree fan-out (deposit-only) path.
	pub(super) private_tx_tx: Option<mpsc::Sender<super::PrivateTxRequest>>,
	/// 4-PI verifier for `/consume-request`. `None` = accept any non-empty proof.
	pub(super) consume_proof_verifier: Option<Arc<LeafProofVerifier>>,
	/// 72-PI verifier for `/private-tx`. `None` = accept any non-empty proof.
	pub(super) tx_proof_verifier: Option<Arc<LeafProofVerifier>>,
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
#[allow(dead_code)]
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
			consume_proof: Some(proof),
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
	// Verify proof AND extract leaf values from PIs (single source of truth).
	// The verifier MUST be configured — without it we cannot trust leaf values.
	let Some(verifier) = state.tx_proof_verifier.as_deref() else {
		warn!(
			tx_id = body.tx_id.as_deref().unwrap_or("unknown"),
			"rejecting private tx: no TX proof verifier configured"
		);
		return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
	};
	let pis = match verifier.verify_and_extract_pis(&tx_proof) {
		Ok(pis) => pis,
		Err(e) => {
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
		},
	};
	info!(
		tx_id = body.tx_id.as_deref().unwrap_or("unknown"),
		proof_len = tx_proof.len(),
		"private tx proof verified, leaves extracted from PIs"
	);

	// Extract AN, AC, NN, NC from proof public inputs.
	let (input_account_leaf, output_account_leaf, input_notes, output_notes) =
		extract_leaves_from_pis(&pis);
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

/// Extract the four tree-leaf groups from already-verified TX proof public inputs.
///
/// Returns `(an, ac, nn, nc)` — the single source of truth for leaf values.
#[allow(clippy::type_complexity)]
fn extract_leaves_from_pis(pis: &[F]) -> ([u8; 32], [u8; 32], Vec<[u8; 32]>, Vec<[u8; 32]>) {
	use plonky2::field::types::PrimeField64;
	// Inner TX proof PI layout (TX_LEAF_PI_SIZE = 77 fields per slot):
	//   PI[0]      = subpool_id_in  (auto-registered by add_virtual_account_target)
	//   PI[1]      = subpool_id_out (auto-registered by add_virtual_account_target)
	//   PI[2]      = subpool_id_in  (explicit re-registration, same wire as PI[0])
	//   PI[3]      = subpool_id_out (explicit re-registration, same wire as PI[1])
	//   PI[4]      = not_fake_tx    (IS_REAL_OFFSET; 1 = real proof, 0 = dummy)
	//   PI[5..9]   = AN  (TX_DATA_OFFSET, 4 fields — account nullifier)
	//   PI[9..13]  = AC  (4 fields — account commitment out)
	//   PI[13..45] = NN  (8×4 fields — note nullifiers)
	//   PI[45..77] = NC  (8×4 fields — note commitments)
	// PI[77..85] (act_root, nct_root) are consumed by the aggregator and not propagated per
	// slot.
	use tessera_trees::proof_aggregation::TX_DATA_OFFSET;

	let f4_to_bytes32 = |fields: &[F]| -> [u8; 32] {
		let mut out = [0u8; 32];
		for (i, f) in fields.iter().enumerate().take(4) {
			out[i * 8..(i + 1) * 8].copy_from_slice(&f.to_canonical_u64().to_be_bytes());
		}
		out
	};

	let an_off = TX_DATA_OFFSET;
	let ac_off = TX_DATA_OFFSET + 4;
	let nn_off = TX_DATA_OFFSET + 8;
	let nc_off = TX_DATA_OFFSET + 40;

	let an = f4_to_bytes32(&pis[an_off..an_off + 4]);
	let ac = f4_to_bytes32(&pis[ac_off..ac_off + 4]);

	let nn: Vec<[u8; 32]> = (0..8)
		.map(|j| f4_to_bytes32(&pis[nn_off + j * 4..nn_off + (j + 1) * 4]))
		.collect();
	let nc: Vec<[u8; 32]> = (0..8)
		.map(|j| f4_to_bytes32(&pis[nc_off + j * 4..nc_off + (j + 1) * 4]))
		.collect();

	(an, ac, nn, nc)
}
