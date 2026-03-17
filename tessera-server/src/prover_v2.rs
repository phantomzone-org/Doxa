//! V2 prover runtime for `TesseraRollupV2`.
//!
//! Replaces the V1 four-tree pipeline with a two-proof design:
//! TX aggregation + SubtreeRootCircuit → SuperAggregatorV2 → BN128 → Groth16.
//!
//! # Types
//!
//! - [`ProveRequestV2`] — sent from Sequencer to Prover.
//! - [`ProveOutcomeV2`] — returned from Prover to Sequencer.
//! - [`ProverRuntimeV2`] — the in-process prover runtime.
//!
//! # Artifact layout (produced by `super_aggregator_v2_artifacts`)
//!
//! ```text
//! artifacts/v2-tx-aggregator/          — TX GenericAggregator
//! artifacts/v2-tx-aggregator/dummy_inner_tx_proof.bin
//! artifacts/subtree-root/              — SubtreeRootCircuit
//! artifacts/super-aggregator-v2/       — SuperAggregatorV2 Plonky2 data
//! artifacts/super-aggregator-v2/plonky2-proof/
//! artifacts/super-aggregator-v2/groth-artifacts/
//! ```

use std::{collections::HashMap, path::Path, time::Duration};

use anyhow::Result;
use plonky2::{field::types::PrimeField64, plonk::proof::ProofWithPublicInputs};
use tessera_trees::{
	groth::{BN128Wrapper, Groth16Wrapper},
	proof_aggregation::{
		validate_subtree_nc_offcircuit, SubtreeRootCircuit, SuperAggregatorV2, TX_LEAF_PI_SIZE,
	},
	tree::hasher::HashOutput,
	ConfigNative, ProofNative, D, F,
};
use tracing::{error, info};

use crate::{
	prover::{build_pool, parse_solidity_proof_json, AssociatedInputAggregatorService},
	types::{ConsumeOutcome, ConsumeProveRequest, ProveOutcomeV2, ProveRequestV2, SolidityProof},
};

// ---------------------------------------------------------------------------
// SubtreeRootProverService
// ---------------------------------------------------------------------------

/// Thin service wrapper around [`SubtreeRootCircuit`].
pub struct SubtreeRootProverService {
	circuit: SubtreeRootCircuit,
}

impl SubtreeRootProverService {
	/// Load from pre-built artifacts at `path`.
	///
	/// `batch_size` must match the size the circuit was built for (= account_batch_size ×
	/// notes_per_slot).
	pub fn from_artifacts(path: &Path, batch_size: usize) -> Result<Self> {
		if !SubtreeRootCircuit::has_artifacts(path) {
			return Err(anyhow::anyhow!(
				"SubtreeRootCircuit artifacts not found at {:?}. \
				 Run `cargo run --bin super_aggregator_v2_artifacts --release` first.",
				path
			));
		}
		info!(batch_size, "loading SubtreeRootCircuit from artifacts");
		let circuit = SubtreeRootCircuit::from_artifacts(path, batch_size)?;
		Ok(Self {
			circuit,
		})
	}

	/// Prove `root = PoseidonMerkle(leaves)`.
	pub fn prove(&self, leaves: &[HashOutput]) -> Result<ProofNative> {
		self.circuit.prove(leaves)
	}

	/// Leaf count this circuit was built for.
	pub fn batch_size(&self) -> usize {
		self.circuit.batch_size()
	}
}

// ---------------------------------------------------------------------------
// SuperAggregatorV2Service
// ---------------------------------------------------------------------------

/// Wraps [`SuperAggregatorV2`] + BN128 + Groth16 for end-to-end proving.
pub struct SuperAggregatorV2Service {
	super_agg: SuperAggregatorV2,
	bn128_wrapper: BN128Wrapper,
}

impl SuperAggregatorV2Service {
	/// Load from pre-built artifacts at `path`.
	///
	/// Also loads the BN128 wrapper and initialises the global Groth16 FFI singleton.
	pub fn from_artifacts(path: &Path) -> Result<Self> {
		if !SuperAggregatorV2::has_artifacts(path) {
			return Err(anyhow::anyhow!(
				"SuperAggregatorV2 artifacts not found at {:?}. \
				 Run `cargo run --bin super_aggregator_v2_artifacts --release` first.",
				path
			));
		}
		info!("loading SuperAggregatorV2 from artifacts");
		let super_agg = SuperAggregatorV2::from_artifacts(path)?;

		let plonky2_path = path.join("plonky2-proof");
		let groth16_artifacts_path = path.join("groth-artifacts");

		if !BN128Wrapper::has_full_artifacts(&plonky2_path) {
			return Err(anyhow::anyhow!(
				"BN128 wrapper artifacts not found at {:?}. \
				 Run `cargo run --bin super_aggregator_v2_artifacts --release` first.",
				plonky2_path
			));
		}
		info!("loading BN128 wrapper (SuperAggregatorV2) from artifacts");
		let bn128_wrapper = BN128Wrapper::from_artifacts(&plonky2_path)?;

		info!("initialising Groth16 singleton for SuperAggregatorV2");
		Groth16Wrapper::init(&plonky2_path, &groth16_artifacts_path)?;
		Groth16Wrapper::check_init();

		Ok(Self {
			super_agg,
			bn128_wrapper,
		})
	}

	/// Stage 1: SAV2 Plonky2 proof (2 inner proofs → root + piCommitment).
	///
	/// Returns `(root_proof, super_pi_commitment_bytes)`.
	pub fn prove_plonky2(
		&self,
		tx_agg: ProofNative,
		sr: ProofNative,
		ac_root: HashOutput,
		nc_root: HashOutput,
		main_pool_cfg_root: [u8; 32],
	) -> Result<(ProofNative, [u8; 32])> {
		let root_proof = self
			.super_agg
			.prove(tx_agg, sr, ac_root, nc_root, main_pool_cfg_root)
			.map_err(|e| anyhow::anyhow!("SAV2 plonky2 prove: {e}"))?;

		let pis = &root_proof.public_inputs;
		anyhow::ensure!(
			pis.len() == 8,
			"SAV2 root must have exactly 8 public inputs, got {}",
			pis.len()
		);
		let mut commitment = [0u8; 32];
		for (i, fi) in pis.iter().enumerate() {
			let word = fi.to_canonical_u64() as u32;
			commitment[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
		}
		Ok((root_proof, commitment))
	}

	/// Stage 2: BN128 wrap + Groth16 prove.
	pub fn wrap_groth16(&self, root_proof: ProofNative) -> Result<SolidityProof> {
		let bn128_proof = self
			.bn128_wrapper
			.wrap_proof_to_bn128(root_proof)
			.map_err(|e| anyhow::anyhow!("SAV2 BN128 wrap: {e}"))?;

		let (g16_proof, g16_pub_inp) =
			Groth16Wrapper::prove(bn128_proof).map_err(|e| anyhow::anyhow!("SAV2 Groth16: {e}"))?;
		let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)
			.map_err(|e| anyhow::anyhow!("SAV2 solidity JSON: {e}"))?;
		Groth16Wrapper::verify(g16_proof, g16_pub_inp)
			.map_err(|e| anyhow::anyhow!("SAV2 Groth16 verify: {e}"))?;
		parse_solidity_proof_json(&solidity_json)
	}
}

// ---------------------------------------------------------------------------
// ProverRuntimeV2
// ---------------------------------------------------------------------------

/// In-process V2 prover runtime.
///
/// Drops the four tree-proof services from V1 and replaces them with:
/// - [`SubtreeRootProverService`] — proves `batchPoseidonRoot = Poseidon(NC leaves)`.
/// - [`SuperAggregatorV2Service`] — merges TX agg + SR → BN128 → Groth16.
///
/// Dummy TX slots use a single pre-loaded fixed proof (is_real=0).
pub struct ProverRuntimeV2 {
	subtree_root: SubtreeRootProverService,
	aggregator: Option<AssociatedInputAggregatorService>,
	super_aggregator: SuperAggregatorV2Service,
	/// Bytes of the pre-computed dummy inner TX proof (is_real=0, all-zero AN/NN).
	dummy_inner_proof_bytes: Vec<u8>,
}

impl ProverRuntimeV2 {
	/// Initialise the V2 prover runtime.
	///
	/// # Parameters
	/// - `sr_artifacts_path`: SubtreeRootCircuit artifact directory.
	/// - `sr_batch_size`: leaf count for the SubtreeRoot circuit (= account_batch_size ×
	///   notes_per_slot).
	/// - `super_aggregator_v2_artifacts_path`: SAV2 artifact directory; also used to load
	///   `dummy_inner_tx_proof.bin`.
	/// - `aggregator_artifacts_path`: when `Some`, loads the V2 TX aggregator for full proving.
	///   When `None` the prover rejects batches with real TX slots.
	/// - `aggregation_prover_urls`: remote aggregation-prover base URLs.
	/// - `aggregation_prover_timeout_secs`: per-request HTTP timeout.
	pub fn init(
		sr_artifacts_path: std::path::PathBuf,
		sr_batch_size: usize,
		super_aggregator_v2_artifacts_path: std::path::PathBuf,
		aggregator_artifacts_path: Option<std::path::PathBuf>,
		aggregation_prover_urls: Vec<String>,
		aggregation_prover_timeout_secs: u64,
	) -> Result<Self> {
		let subtree_root =
			SubtreeRootProverService::from_artifacts(&sr_artifacts_path, sr_batch_size)?;

		let super_aggregator =
			SuperAggregatorV2Service::from_artifacts(&super_aggregator_v2_artifacts_path)?;

		// Load pre-computed dummy inner TX proof from the SAV2 artifact directory.
		let dummy_path = super_aggregator_v2_artifacts_path.join("dummy_inner_tx_proof.bin");
		let dummy_inner_proof_bytes = std::fs::read(&dummy_path).map_err(|e| {
			anyhow::anyhow!(
				"failed to read dummy_inner_tx_proof.bin from {:?}: {e}",
				dummy_path
			)
		})?;
		info!(
			bytes = dummy_inner_proof_bytes.len(),
			"loaded dummy inner TX proof"
		);

		let timeout = Duration::from_secs(aggregation_prover_timeout_secs);
		let pool = build_pool(
			aggregator_artifacts_path.as_deref(),
			&aggregation_prover_urls,
			timeout,
		)?;
		let aggregator = aggregator_artifacts_path
			.map(|path| AssociatedInputAggregatorService::from_artifacts_and_pool(&path, pool))
			.transpose()?;

		Ok(Self {
			subtree_root,
			aggregator,
			super_aggregator,
			dummy_inner_proof_bytes,
		})
	}

	/// Build and aggregate TX leaf proofs for a V2 batch.
	///
	/// Real slots (present in `tx_proofs_by_slot`) use the client-supplied proof.
	/// All other slots, including padding to the aggregation tree width, use the
	/// pre-loaded fixed dummy proof (`is_real=0`).  No per-slot AN/NN override is
	/// needed in V2 because there is no multiset equality constraint.
	fn build_and_aggregate_tx_proofs(
		aggregator: &Option<AssociatedInputAggregatorService>,
		account_batch_size: usize,
		tx_proofs_by_slot: &HashMap<usize, Vec<u8>>,
		dummy_proof_bytes: &[u8],
	) -> Result<ProofNative> {
		let Some(agg_service) = aggregator else {
			anyhow::bail!("no TX aggregator configured (set TESSERA_AGGREGATOR_ARTIFACTS_PATH)");
		};

		let mut leaf_proofs: Vec<Vec<u8>> = Vec::with_capacity(account_batch_size);
		for s in 0..account_batch_size {
			if let Some(inner_proof_bytes) = tx_proofs_by_slot.get(&s) {
				// Real slot: validate proof structure, then use as-is.
				ProofWithPublicInputs::<F, ConfigNative, D>::from_bytes(
					inner_proof_bytes.clone(),
					&agg_service.inner_circuit.common,
				)
				.map_err(|e| anyhow::anyhow!("slot {s} proof deser: {e:?}"))?;
				leaf_proofs.push(inner_proof_bytes.clone());
			} else {
				// Padding / empty slot: use fixed dummy proof.
				leaf_proofs.push(dummy_proof_bytes.to_vec());
			}
		}

		// Pad to full aggregation tree width.
		let n_leaves = agg_service.n_leaves();
		anyhow::ensure!(
			leaf_proofs.len() <= n_leaves,
			"batch size ({}) > aggregation tree leaf count ({})",
			leaf_proofs.len(),
			n_leaves
		);
		for _ in leaf_proofs.len()..n_leaves {
			leaf_proofs.push(dummy_proof_bytes.to_vec());
		}

		let root_proof = tokio::runtime::Handle::current()
			.block_on(agg_service.aggregate_bytes(&leaf_proofs))
			.map_err(|e| anyhow::anyhow!("TX aggregation: {e}"))?;

		Ok(root_proof)
	}

	/// Prove a single [`ConsumeProveRequest`] end-to-end.
	///
	/// This is a placeholder implementation that reuses the TX SuperAggregatorV2 pipeline.
	/// A dedicated consume SA circuit (with `depositVerifier`) will replace this in a
	/// future phase once the consume-circuit artifacts are built.
	pub fn prove_consume_request(&mut self, request: ConsumeProveRequest) -> ConsumeOutcome {
		let batch_id = request.batch_id;
		// Map ConsumeProveRequest → ProveRequestV2 (same structure; proofs keyed by note index).
		let tx_request = ProveRequestV2 {
			batch_id,
			nc_leaves: request.nc_leaves,
			ac_root: request.ac_root,
			nc_root: request.nc_root,
			main_pool_cfg_root: request.main_pool_cfg_root,
			tx_proofs_by_slot: request.consume_proofs_by_slot,
		};
		match self.try_prove_request_v2(tx_request) {
			Ok(ProveOutcomeV2::Success {
				batch_poseidon_root,
				solidity_proof,
				super_pi_commitment,
				..
			}) => ConsumeOutcome::Success {
				batch_id,
				batch_poseidon_root,
				solidity_proof,
				super_pi_commitment,
			},
			Ok(ProveOutcomeV2::Failure {
				error, ..
			}) => ConsumeOutcome::Failure {
				batch_id,
				error,
			},
			Err(e) => {
				error!(batch_id, error = %e, "prove_consume_request failed");
				ConsumeOutcome::Failure {
					batch_id,
					error: e.to_string(),
				}
			},
		}
	}

	/// Prove a single [`ProveRequestV2`] end-to-end.
	pub fn prove_request_v2(&mut self, request: ProveRequestV2) -> ProveOutcomeV2 {
		let batch_id = request.batch_id;
		match self.try_prove_request_v2(request) {
			Ok(outcome) => outcome,
			Err(e) => {
				error!(batch_id, error = %e, "prove request V2 failed");
				ProveOutcomeV2::Failure {
					batch_id,
					error: e.to_string(),
				}
			},
		}
	}

	/// Inner proving pipeline (uses `?` for propagation).
	fn try_prove_request_v2(&mut self, request: ProveRequestV2) -> Result<ProveOutcomeV2> {
		let batch_id = request.batch_id;
		let notes_per_slot = tessera_client::NOTE_BATCH;
		let sr_batch_size = self.subtree_root.batch_size();
		let account_batch_size = sr_batch_size / notes_per_slot;

		anyhow::ensure!(
			request.nc_leaves.len() == sr_batch_size,
			"nc_leaves length ({}) != sr_batch_size ({})",
			request.nc_leaves.len(),
			sr_batch_size,
		);

		// ── 1. Build & aggregate TX leaf proofs ─────────────────────────────
		info!(batch_id, account_batch_size, "building TX leaf proofs (V2)");
		let tx_agg_proof = Self::build_and_aggregate_tx_proofs(
			&self.aggregator,
			account_batch_size,
			&request.tx_proofs_by_slot,
			&self.dummy_inner_proof_bytes,
		)
		.map_err(|e| anyhow::anyhow!("build_and_aggregate_tx_proofs: {e}"))?;

		// ── 2. Convert nc_leaves bytes to HashOutput ─────────────────────────
		let nc_hashes: Vec<HashOutput> = request.nc_leaves.iter().map(bytes32_to_hash).collect();

		// ── 3. Prove SubtreeRootCircuit ──────────────────────────────────────
		info!(batch_id, sr_batch_size, "proving SubtreeRootCircuit");
		let sr_proof = self
			.subtree_root
			.prove(&nc_hashes)
			.map_err(|e| anyhow::anyhow!("SubtreeRootCircuit prove: {e}"))?;

		let batch_poseidon_root = SubtreeRootCircuit::root_from_proof(&sr_proof);

		// ── 4. Off-circuit cross-check (NC in TX proof ↔ SR leaves) ─────────
		let n_tx_slots = tx_agg_proof.public_inputs.len() / TX_LEAF_PI_SIZE;
		anyhow::ensure!(
			n_tx_slots >= account_batch_size,
			"TX n_tx_slots ({n_tx_slots}) < account_batch_size ({account_batch_size})"
		);
		info!(batch_id, n_tx_slots, "running off-circuit NC cross-check");
		validate_subtree_nc_offcircuit(
			&sr_proof.public_inputs,
			&tx_agg_proof.public_inputs,
			n_tx_slots,
			notes_per_slot,
		)
		.map_err(|e| anyhow::anyhow!("off-circuit NC cross-check: {e}"))?;
		info!(batch_id, "off-circuit NC cross-check passed");

		// ── 5. SuperAggregatorV2 Plonky2 proof ──────────────────────────────
		info!(batch_id, "running SuperAggregatorV2 Plonky2 proof");
		let (sa_root_proof, super_pi_commitment) = self
			.super_aggregator
			.prove_plonky2(
				tx_agg_proof,
				sr_proof,
				request.ac_root,
				request.nc_root,
				request.main_pool_cfg_root,
			)
			.map_err(|e| anyhow::anyhow!("SAV2 plonky2: {e}"))?;

		info!(
			batch_id,
			super_pi_commitment = hex::encode(super_pi_commitment),
			"SAV2 Plonky2 done, wrapping (BN128 + Groth16)"
		);

		// ── 6. BN128 + Groth16 wrap ──────────────────────────────────────────
		let solidity_proof = self
			.super_aggregator
			.wrap_groth16(sa_root_proof)
			.map_err(|e| anyhow::anyhow!("SAV2 Groth16: {e}"))?;

		Ok(ProveOutcomeV2::Success {
			batch_id,
			batch_poseidon_root,
			solidity_proof: Box::new(solidity_proof),
			super_pi_commitment,
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a 32-byte big-endian leaf to a [`HashOutput`].
///
/// Each 8-byte chunk becomes one Goldilocks field element in canonical form.
fn bytes32_to_hash(b: &[u8; 32]) -> HashOutput {
	use plonky2::field::types::Field;
	HashOutput::new(core::array::from_fn(|i| {
		let val = u64::from_be_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
		F::from_canonical_u64(val)
	}))
}
