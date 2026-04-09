use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use plonky2::plonk::proof::ProofWithPublicInputs;
use tessera_utils::{hasher::HashOutput, ConfigNative, ProofNative, D, F};
use tracing::{error, info};

use crate::{
	aggregation_pipeline::{
		start_aggregation_session, AsyncNodeProver, LocalAsyncNodeProver, NodeProverPool,
		RemoteNodeProver,
	},
	proof_aggregation::{
		validate_subtree_nc_offcircuit, GenericAggregator, SubtreeRootCircuit, SuperAggregator,
		TX_LEAF_PI_SIZE,
	},
	sequencer::BN128WrapperService,
	types::{ProveOutcome, ProveRequest, SolidityProof},
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
	/// `batch_size` must match the size the circuit was built for (= priv_tx_batch_size ×
	/// notes_per_slot).
	pub fn from_artifacts(path: &Path, batch_size: usize) -> Result<Self> {
		if !SubtreeRootCircuit::has_artifacts(path) {
			return Err(anyhow::anyhow!(
				"SubtreeRootCircuit artifacts not found at {:?}. \
				 Run `cargo run --bin super_aggregator_artifacts --release` first.",
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
// ProverRuntime
// ---------------------------------------------------------------------------

/// In-process V2 prover runtime.
///
/// Drops the four tree-proof services from V1 and replaces them with:
/// - [`SubtreeRootProverService`] — proves `batchPoseidonRoot = Poseidon(NC leaves)`.
/// - [`SuperAggregatorService`] — merges TX agg + SR → BN128 → Groth16.
///
/// Optionally also holds the deposit pipeline (loaded via [`DepositPipelineConfig`]).
pub struct TransactionProverRuntime {
	subtree_root: SubtreeRootProverService,
	aggregator: Option<AssociatedInputAggregatorService>,
	bn128_wrapper_service: BN128WrapperService,
	/// Bytes of the pre-computed dummy inner TX proof (is_real=0).
	dummy_inner_proof_bytes: Vec<u8>,
}

impl TransactionProverRuntime {
	/// Initialise the V2 prover runtime.
	///
	/// # Parameters
	/// - `sr_artifacts_path`: SubtreeRootCircuit artifact directory.
	/// - `sr_batch_size`: leaf count for the SubtreeRoot circuit (= priv_tx_batch_size ×
	///   notes_per_slot).
	/// - `super_aggregator_artifacts_path`: Final Plonky2 Proof artifact directory; also used to
	///   load `dummy_inner_tx_proof.bin`.
	/// - `aggregator_artifacts_path`: when `Some`, loads the V2 TX aggregator for full proving.
	///   When `None` the prover rejects batches with real TX slots.
	/// - `aggregation_prover_urls`: remote aggregation-prover base URLs.
	/// - `aggregation_prover_timeout_secs`: per-request HTTP timeout.
	pub fn init(
		sr_artifacts_path: std::path::PathBuf,
		sr_batch_size: usize,
		super_aggregator_artifacts_path: std::path::PathBuf,
		aggregator_artifacts_path: Option<std::path::PathBuf>,
		aggregation_prover_urls: Vec<String>,
		aggregation_prover_timeout_secs: u64,
	) -> Result<Self> {
		let subtree_root =
			SubtreeRootProverService::from_artifacts(&sr_artifacts_path, sr_batch_size)?;

		let bn128_wrapper_service =
			BN128WrapperService::from_artifacts(&super_aggregator_artifacts_path)?;

		// Load pre-computed dummy inner TX proof from the Final Plonky2 Proof artifact directory.
		let dummy_path = super_aggregator_artifacts_path.join("dummy_inner_tx_proof.bin");
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
			bn128_wrapper_service,
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
		tx_proofs_by_slot: &HashMap<usize, Vec<u8>>,
		dummy_proof_bytes: &[u8],
	) -> Result<ProofNative> {
		let Some(agg_service) = aggregator else {
			anyhow::bail!("no TX aggregator configured (set TESSERA_AGGREGATOR_ARTIFACTS_PATH)");
		};

		let mut leaf_proofs: Vec<Vec<u8>> = Vec::with_capacity(tessera_client::PRIV_TX_BATCH_SIZE);
		for s in 0..tessera_client::PRIV_TX_BATCH_SIZE {
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

	/// Prove a single [`ProveRequest`] end-to-end.
	pub fn prove_request(&mut self, request: ProveRequest) -> ProveOutcome {
		let batch_id = request.batch_id;
		match self.try_prove_request(request) {
			Ok(outcome) => outcome,
			Err(e) => {
				error!(batch_id, error = %e, "prove request V2 failed");
				ProveOutcome::Failure {
					batch_id,
					error: e.to_string(),
				}
			},
		}
	}

	/// Inner proving pipeline (uses `?` for propagation).
	fn try_prove_request(&mut self, request: ProveRequest) -> Result<ProveOutcome> {
		let batch_id = request.batch_id;
		// SR has NOTE_BATCH NC leaves + 1 AC leaf per TX slot = NOTE_BATCH+1 leaves per slot.
		let notes_per_slot = tessera_client::NOTE_BATCH + 1;
		let sr_batch_size = self.subtree_root.batch_size();
		let priv_tx_batch_size = sr_batch_size / notes_per_slot;

		anyhow::ensure!(
			request.nc_leaves.len() == sr_batch_size,
			"nc_leaves length ({}) != sr_batch_size ({})",
			request.nc_leaves.len(),
			sr_batch_size,
		);

		// ── 1. Build & aggregate TX leaf proofs ─────────────────────────────
		info!(batch_id, "building TX leaf proofs (V2)");
		let tx_agg_proof = Self::build_and_aggregate_tx_proofs(
			&self.aggregator,
			&request.tx_proofs_by_slot,
			&self.dummy_inner_proof_bytes,
		)
		.map_err(|e| anyhow::anyhow!("build_and_aggregate_tx_proofs: {e}"))?;

		// ── 2. Convert nc_leaves bytes to HashOutput ─────────────────────────
		let nc_hashes: Vec<HashOutput> = request
			.nc_leaves
			.iter()
			.map(|c| HashOutput::from_encoded_fields_unchecked(*c))
			.collect();

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
			n_tx_slots >= priv_tx_batch_size,
			"TX n_tx_slots ({n_tx_slots}) < priv_tx_batch_size ({priv_tx_batch_size})"
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

		// ── DEBUG: print all TX piCommitment preimage inputs ─────────────
		{
			let nc_per_slot = notes_per_slot - 1; // 7
			let acs = SuperAggregator::acs_from_tx_proof(&tx_agg_proof, n_tx_slots);
			let ans = SuperAggregator::ans_from_tx_proof(&tx_agg_proof, n_tx_slots);
			let ncs = SuperAggregator::ncs_from_sr_proof(
				&sr_proof,
				n_tx_slots,
				notes_per_slot,
				nc_per_slot,
			);
			let nns = SuperAggregator::nn_from_tx_proof(
				&tx_agg_proof,
				n_tx_slots,
				tessera_client::NOTE_BATCH,
			);

			let root_u256 = crate::contract::hash_to_u256_le(&request.root);
			let bpr_u256 = crate::contract::hash_to_u256_le(&batch_poseidon_root);

			eprintln!(
				"[TX-PROVER] root              : {}",
				hex::encode(root_u256.to_be_bytes::<32>())
			);
			eprintln!(
				"[TX-PROVER] mainPoolCfgRoot    : {}",
				hex::encode(request.main_pool_cfg_root)
			);
			eprintln!(
				"[TX-PROVER] batchPoseidonRoot  : {}",
				hex::encode(bpr_u256.to_be_bytes::<32>())
			);
			eprintln!("[TX-PROVER] accountCommitments : {}", acs.len());
			eprintln!("[TX-PROVER] accountNullifiers  : {}", ans.len());
			eprintln!("[TX-PROVER] noteCommitments len: {}", ncs.len());
			for (i, nc) in ncs.iter().enumerate().take(3) {
				let v = crate::contract::hash_to_u256_le(nc);
				eprintln!(
					"[TX-PROVER] nc[{:>3}]            : {}",
					i,
					hex::encode(v.to_be_bytes::<32>())
				);
			}
			eprintln!("[TX-PROVER] noteNullifiers len : {}", nns.len());
			for (i, nn) in nns.iter().enumerate().take(3) {
				let v = crate::contract::hash_to_u256_le(nn);
				eprintln!(
					"[TX-PROVER] nn[{:>3}]            : {}",
					i,
					hex::encode(v.to_be_bytes::<32>())
				);
			}

			let native = SuperAggregator::compute_pi_commitment_native(
				request.root,
				request.main_pool_cfg_root,
				batch_poseidon_root,
				&acs,
				&ans,
				&ncs,
				&nns,
			);
			let native_hex: String = native
				.iter()
				.map(|w| format!("{:08x}", w))
				.collect::<Vec<_>>()
				.join("");
			eprintln!("[TX-PROVER] native commitment  : {}", native_hex);
		}

		// ── 5. SuperAggregator Plonky2 proof ──────────────────────────────
		info!(batch_id, "running SuperAggregator Plonky2 proof");
		// TODO: add aggregator service:
		// let (sa_root_proof, super_pi_commitment) = self
		// .aggregator_service
		// .prove_plonky2(
		// tx_agg_proof,
		// sr_proof,
		// request.root,
		// request.main_pool_cfg_root,
		// )
		// .map_err(|e| anyhow::anyhow!("Final Plonky2 Proof plonky2: {e}"))?;

		let sa_root_proof = None; // TODO: replace with actual value
		let super_pi_commitment = [0u8; 32]; // TODO: replace with actual value

		eprintln!(
			"[TX-PROVER] circuit commitment : {}",
			hex::encode(super_pi_commitment)
		);
		info!(
			batch_id,
			super_pi_commitment = hex::encode(super_pi_commitment),
			"Final Plonky2 Proof Plonky2 done, wrapping (BN128 + Groth16)"
		);

		// ── 6. BN128 + Groth16 wrap ──────────────────────────────────────────
		let solidity_proof = self
			.bn128_wrapper_service
			.wrap_groth16(sa_root_proof.unwrap())
			.map_err(|e| anyhow::anyhow!("Final Plonky2 Proof Groth16: {e}"))?;

		Ok(ProveOutcome::Success {
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

/// Mirror of Solidity `TesseraContract.keccakToPublicInputs`.
///
/// Splits a 32-byte Keccak-256 piCommitment into 8 big-endian uint32 words,
/// matching the gnark Groth16 verifier's public input layout.
///
/// This is the inverse of the packing done in `SuperAggregatorV2Service::prove_plonky2`:
/// `commitment[i*4..(i+1)*4] = word[i].to_be_bytes()`.
pub fn keccak_to_public_inputs(commitment: &[u8; 32]) -> [u32; 8] {
	core::array::from_fn(|i| u32::from_be_bytes(commitment[i * 4..(i + 1) * 4].try_into().unwrap()))
}



/// Build a [`NodeProverPool`] for TX-aggregation-tree node proving.
///
/// When `aggregator_artifacts_path` is supplied and the artifacts are present,
/// the pool contains one local prover plus one remote prover per URL.
/// If artifacts are absent or the path is `None`, the returned pool is empty.
pub fn build_pool(
	aggregator_artifacts_path: Option<&Path>,
	remote_urls: &[String],
	timeout: Duration,
) -> Result<Arc<NodeProverPool<F, ConfigNative, D>>> {
	let mut provers: Vec<Arc<dyn AsyncNodeProver<F, ConfigNative, D>>> = Vec::new();

	if let Some(path) = aggregator_artifacts_path {
		if GenericAggregator::<F, ConfigNative, D>::has_full_artifacts(path)? {
			let agg = Arc::new(GenericAggregator::<F, ConfigNative, D>::from_artifacts(
				path,
				&tessera_client::TesseraGateSerializer,
			)?);

			provers.push(Arc::new(LocalAsyncNodeProver::new(agg.clone())));

			for url in remote_urls {
				let remote = RemoteNodeProver::new(url, agg.clone(), timeout)?;
				provers.push(Arc::new(remote));
			}
		}
	}

	Ok(Arc::new(NodeProverPool::new(provers)))
}

/// Aggregates `PrivateTx` leaf proofs into a single root Plonky2 proof using
/// the streaming aggregation pipeline. Loaded from pre-built artifacts.
pub struct AssociatedInputAggregatorService {
	aggregator: Arc<GenericAggregator<F, ConfigNative, D>>,
	pool: Arc<NodeProverPool<F, ConfigNative, D>>,
	/// The inner PrivTx circuit data (needed for proof deserialization).
	pub(crate) inner_circuit: tessera_utils::CircuitDataNative,
}

impl AssociatedInputAggregatorService {
	/// Load from pre-built aggregator artifacts at `path`, using `pool` for
	/// distributed node proving.
	pub fn from_artifacts_and_pool(
		path: &Path,
		pool: Arc<NodeProverPool<F, ConfigNative, D>>,
	) -> Result<Self> {
		if !GenericAggregator::<F, ConfigNative, D>::has_full_artifacts(path)? {
			return Err(anyhow::anyhow!(
				"aggregator artifacts not found at {:?}. \
				 Run `cargo run --bin aggregator_artifacts --release` first.",
				path
			));
		}
		info!("loading associated input aggregator from artifacts");
		let aggregator = GenericAggregator::<F, ConfigNative, D>::from_artifacts(
			path,
			&tessera_client::TesseraGateSerializer,
		)?;

		info!("building inner PrivTx circuit for proof deserialization");
		let (inner_circuit, _inner_targets) = tessera_client::build_priv_tx_circuit();
		info!(
			inner_pi = inner_circuit.common.num_public_inputs,
			inner_degree_bits = inner_circuit.common.degree_bits(),
			"inner PrivTx circuit ready"
		);

		Ok(Self {
			aggregator: Arc::new(aggregator),
			pool,
			inner_circuit,
		})
	}

	/// Total leaf count of the underlying aggregation tree (`arity^depth`).
	pub(crate) fn n_leaves(&self) -> usize {
		let cfg = self.aggregator.config();
		cfg.arity.pow(cfg.depth as u32)
	}

	/// Submit all leaf proof bytes to a streaming session and await the root proof.
	pub async fn aggregate_bytes(&self, proof_bytes: &[Vec<u8>]) -> Result<ProofNative> {
		let (handle, root_fut) =
			start_aggregation_session(self.aggregator.clone(), self.pool.clone());

		for (i, bytes) in proof_bytes.iter().enumerate() {
			handle.submit_bytes(i, bytes.clone()).await?;
		}
		drop(handle);

		let root = root_fut.await?;
		self.aggregator.verify_root(&root)?;
		Ok(root)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Verify that packing 8 u32 words big-endian into a bytes32 (the logic in
	/// `prove_plonky2`) is the exact inverse of `keccak_to_public_inputs`, which
	/// mirrors the Solidity `keccakToPublicInputs` function.
	///
	/// This guarantees that the gnark public inputs and the on-chain
	/// `keccakToPublicInputs(piCommitment)` decomposition are consistent.
	#[test]
	fn test_pi_commitment_encoding_round_trip() {
		let words: [u32; 8] = [
			0xDEAD_BEEF,
			0x0123_4567,
			0x89AB_CDEF,
			0xFEDC_BA98,
			0x1122_3344,
			0x5566_7788,
			0x99AA_BBCC,
			0x00FF_00FF,
		];

		// Pack words → bytes32 (same logic as prove_plonky2).
		let mut commitment = [0u8; 32];
		for (i, &w) in words.iter().enumerate() {
			commitment[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
		}

		// Unpack bytes32 → words (mirrors Solidity keccakToPublicInputs).
		let unpacked = keccak_to_public_inputs(&commitment);
		assert_eq!(unpacked, words);
	}
}
