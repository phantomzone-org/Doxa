use std::{path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use plonky2::{
	field::types::PrimeField64,
	iop::witness::PartialWitness,
	plonk::{
		circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, proof::ProofWithPublicInputs,
	},
};
use tessera_trees::{
	groth::{BN128Wrapper, Groth16Wrapper},
	proof_aggregation::{
		validate_ac_offcircuit, validate_an_offcircuit, validate_nc_offcircuit,
		validate_nn_offcircuit, GenericAggregator, SuperAggregator, LEAF_OFFSET, TX_DATA_OFFSET,
		TX_LEAF_PI_SIZE,
	},
	tree::{
		hasher::{HashOutput, MerkleHashCircuit},
		BatchCommitmentProof, BatchCommitmentProofTargets, BatchInsertProof,
		BatchNullifierInsertProofTargets,
	},
	CircuitDataNative, ConfigNative, ProofNative, D, F,
};
use tracing::{error, info};

use crate::{
	aggregation_pipeline::{
		start_aggregation_session, AsyncNodeProver, LocalAsyncNodeProver, NodeProverPool,
		RemoteNodeProver,
	},
	sequencer::batch::is_sorted_u256,
	types::{ProveOutcome, ProveRequest, SolidityProof},
};

/// Encapsulates the commitment-tree proof pipeline (notes or accounts).
///
/// Holds the compiled plonky2 circuit and its public-input targets.
/// Produces a raw Plonky2 proof; wrapping is handled centrally by
/// [`SuperAggregatorService`].
pub struct CommitmentProverService {
	circuit_data: CircuitDataNative,
	targets: BatchCommitmentProofTargets<4>,
}

/// Encapsulates the nullifier-tree proof pipeline (notes or accounts).
///
/// Mirrors [`CommitmentProverService`] but uses `BatchNullifierInsertProofTargets`.
pub struct NullifierProverService {
	circuit_data: CircuitDataNative,
	targets: BatchNullifierInsertProofTargets<4>,
}

/// Aggregates `PrivateTx` leaf proofs into a single root Plonky2 proof using
/// the streaming aggregation pipeline.
///
/// Loaded from pre-built artifacts.  The root proof is passed to
/// [`SuperAggregatorService`] for the final BN128/Groth16 wrapping step.
pub struct AssociatedInputAggregatorService {
	aggregator: Arc<GenericAggregator<F, ConfigNative, D>>,
	pool: Arc<NodeProverPool<F, ConfigNative, D>>,
	/// The inner PrivTx circuit data (needed for proof deserialization and dummy proving).
	pub(crate) inner_circuit: CircuitDataNative,
	/// The inner PrivTx circuit targets (needed for dummy proving with overrides).
	inner_targets: tessera_client::PrivTxTargets<D>,
}

/// Merges 5 independent inner Plonky2 proofs into a single Groth16 proof via
/// the SuperAggregator circuit, then BN128-wraps and Groth16-proves the result.
pub struct SuperAggregatorService {
	super_agg: SuperAggregator,
	bn128_wrapper: BN128Wrapper,
}

impl CommitmentProverService {
	/// Build the commitment-tree circuit in memory for the given `batch_size`.
	///
	/// No artifact files are read; the circuit is deterministically constructed
	/// from `batch_size` and must match the inner circuit baked into the
	/// SuperAggregator artifacts.
	pub fn init(batch_size: usize) -> Result<Self> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		HashOutput::register_luts(&mut builder);
		let targets =
			BatchCommitmentProofTargets::new::<HashOutput, F, D>(&mut builder, 32, batch_size);
		targets.connect::<HashOutput, F, D>(&mut builder, &());
		let circuit_data = builder.build::<ConfigNative>();
		info!(batch_size, "commitment prover initialized");
		Ok(Self {
			circuit_data,
			targets,
		})
	}

	/// Generate a native Plonky2 proof for the given commitment batch.
	pub fn prove(&self, batch_proof: &BatchCommitmentProof<HashOutput>) -> Result<ProofNative> {
		let mut pw = PartialWitness::new();
		self.targets
			.set::<HashOutput, F, D, 32>(&mut pw, batch_proof)
			.map_err(|e| anyhow::anyhow!("commitment tree set witness: {e}"))?;
		let proof = self
			.circuit_data
			.prove(pw)
			.map_err(|e| anyhow::anyhow!("commitment tree prove: {e}"))?;
		self.circuit_data
			.verify(proof.clone())
			.map_err(|e| anyhow::anyhow!("commitment tree verify: {e}"))?;
		Ok(proof)
	}
}

impl NullifierProverService {
	/// Build the nullifier-tree circuit in memory for the given `batch_size`.
	///
	/// No artifact files are read; the circuit is deterministically constructed
	/// from `batch_size` and must match the inner circuit baked into the
	/// SuperAggregator artifacts.
	pub fn init(batch_size: usize) -> Result<Self> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		HashOutput::register_luts(&mut builder);
		let targets =
			BatchNullifierInsertProofTargets::new::<HashOutput, F, D>(&mut builder, 32, batch_size);
		targets.connect::<HashOutput, F, D>(&mut builder, &());
		let circuit_data = builder.build::<ConfigNative>();
		info!(batch_size, "nullifier prover initialized");
		Ok(Self {
			circuit_data,
			targets,
		})
	}

	/// Generate a native Plonky2 proof for the given nullifier batch.
	pub fn prove(&self, batch_proof: &BatchInsertProof<HashOutput>) -> Result<ProofNative> {
		let mut pw = PartialWitness::new();
		self.targets
			.set::<HashOutput, F, D>(&mut pw, batch_proof)
			.map_err(|e| anyhow::anyhow!("nullifier tree set witness: {e}"))?;
		let proof = self
			.circuit_data
			.prove(pw)
			.map_err(|e| anyhow::anyhow!("nullifier tree prove: {e}"))?;
		self.circuit_data
			.verify(proof.clone())
			.map_err(|e| anyhow::anyhow!("nullifier tree verify: {e}"))?;
		Ok(proof)
	}
}

impl AssociatedInputAggregatorService {
	/// Load from pre-built aggregator artifacts at `path`, using `pool` for
	/// distributed node proving.
	///
	/// Expects the standard layout produced by `cargo run --bin aggregator_artifacts --release`:
	/// native Plonky2 aggregator data directly under `path`, plus `dummy_inner_proof.bin`.
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

		// Rebuild the inner PrivTx circuit deterministically (same as artifact generation).
		info!("building inner PrivTx circuit for proof deserialization + dummy proving");
		let (inner_circuit, inner_targets) = tessera_client::build_priv_tx_circuit();
		info!(
			inner_pi = inner_circuit.common.num_public_inputs,
			inner_degree_bits = inner_circuit.common.degree_bits(),
			"inner PrivTx circuit ready"
		);

		Ok(Self {
			aggregator: Arc::new(aggregator),
			pool,
			inner_circuit,
			inner_targets,
		})
	}

	/// Deserialize an inner PrivTx proof and return it as leaf proof bytes.
	///
	/// With the recursive leaf removed, the inner proof IS the leaf proof.
	/// Deserialization validates the proof structure against the inner circuit.
	fn prove_leaf(&self, inner_proof_bytes: &[u8]) -> Result<Vec<u8>> {
		// Deserialize to validate structure; re-serialize for the aggregator.
		let _inner_proof = ProofWithPublicInputs::<F, ConfigNative, D>::from_bytes(
			inner_proof_bytes.to_vec(),
			&self.inner_circuit.common,
		)?;
		Ok(inner_proof_bytes.to_vec())
	}

	/// Generate a dummy inner proof with specific AN/NN override values.
	///
	/// The override values become the proof's public inputs for the
	/// account-nullifier and note-nullifier fields, matching the tree
	/// padding so the SuperAggregator's multi-set equality passes.
	fn prove_dummy_leaf(
		&self,
		seed: u64,
		override_an: [F; 4],
		override_nn: [[F; 4]; tessera_client::NOTE_BATCH],
	) -> Result<Vec<u8>> {
		let proof = tessera_client::prove_dummy_priv_tx(
			&self.inner_circuit,
			&self.inner_targets,
			seed,
			override_an,
			override_nn,
		);
		Ok(proof.to_bytes())
	}

	/// Total leaf count of the underlying aggregation tree (`arity^depth`).
	pub(crate) fn n_leaves(&self) -> usize {
		let cfg = self.aggregator.config();
		cfg.arity.pow(cfg.depth as u32)
	}

	/// Submit all leaf proof bytes to a streaming session, await the root proof.
	///
	/// Uses the [`NodeProverPool`] configured at construction time.
	pub async fn aggregate_bytes(&self, proof_bytes: &[Vec<u8>]) -> Result<ProofNative> {
		let (handle, root_fut) =
			start_aggregation_session(self.aggregator.clone(), self.pool.clone());

		for (i, bytes) in proof_bytes.iter().enumerate() {
			handle.submit_bytes(i, bytes.clone()).await?;
		}
		// Drop the handle so the actor can detect completion.
		drop(handle);

		let root = root_fut.await?;
		self.aggregator.verify_root(&root)?;
		Ok(root)
	}
}

impl SuperAggregatorService {
	/// Load from pre-built SuperAggregator artifacts at `path`.
	///
	/// Expects:
	/// - `{path}/` — SuperAggregator Plonky2 circuit data (`.bin` files)
	/// - `{path}/plonky2-proof/` — BN128 wrapper artifacts
	/// - `{path}/groth-artifacts/` — Groth16 trusted-setup artifacts
	///
	/// Also initialises the global Groth16 FFI singleton for this circuit.
	pub fn from_artifacts(path: &Path) -> Result<Self> {
		if !SuperAggregator::has_artifacts(path) {
			return Err(anyhow::anyhow!(
				"SuperAggregator artifacts not found at {:?}. \
				 Run `cargo run --bin super_aggregator_artifacts --release` first.",
				path
			));
		}
		info!("loading SuperAggregator from artifacts");
		let super_agg = SuperAggregator::from_artifacts(path)?;

		let plonky2_path = path.join("plonky2-proof");
		let groth16_artifacts_path = path.join("groth-artifacts");

		if !BN128Wrapper::has_full_artifacts(&plonky2_path) {
			return Err(anyhow::anyhow!(
				"BN128 wrapper artifacts not found at {:?}. \
				 Run `cargo run --bin super_aggregator_artifacts --release` first.",
				plonky2_path
			));
		}
		info!("loading BN128 wrapper (super aggregator) from artifacts");
		let bn128_wrapper = BN128Wrapper::from_artifacts(&plonky2_path)?;

		info!("initialising Groth16 singleton for SuperAggregator");
		Groth16Wrapper::init(&plonky2_path, &groth16_artifacts_path)?;
		Groth16Wrapper::check_init();

		Ok(Self {
			super_agg,
			bn128_wrapper,
		})
	}

	/// Stage 1: SA Plonky2 proof (5 inner proofs → root proof + commitment).
	///
	/// Returns `(root_proof, super_pi_commitment)` where
	/// `super_pi_commitment` is the 32-byte Keccak digest packed from the
	/// root proof's 8 public inputs (one u32 word each, big-endian).
	///
	/// Does not touch BN128/Groth16.
	pub fn prove_plonky2(
		&self,
		nc: ProofNative,
		nn: ProofNative,
		ac: ProofNative,
		an: ProofNative,
		tx_agg: ProofNative,
	) -> Result<(ProofNative, [u8; 32])> {
		let root_proof = self
			.super_agg
			.prove(nc, nn, ac, an, tx_agg)
			.map_err(|e| anyhow::anyhow!("SA plonky2 prove: {e}"))?;

		let pis = &root_proof.public_inputs;
		anyhow::ensure!(
			pis.len() == 8,
			"SuperAggregator root must have exactly 8 public inputs, got {}",
			pis.len()
		);
		let mut commitment = [0u8; 32];
		for (i, fi) in pis.iter().enumerate() {
			let word = fi.to_canonical_u64() as u32;
			commitment[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
		}

		Ok((root_proof, commitment))
	}

	/// Stage 2: BN128 wrap + Groth16 prove of a SA root proof.
	///
	/// Takes the root proof from [`prove_plonky2`] and returns the
	/// Solidity-ready proof.
	pub fn wrap_groth16(&self, root_proof: ProofNative) -> Result<SolidityProof> {
		let bn128_proof = self
			.bn128_wrapper
			.wrap_proof_to_bn128(root_proof)
			.map_err(|e| anyhow::anyhow!("SA BN128 wrap: {e}"))?;

		let (g16_proof, g16_pub_inp) =
			Groth16Wrapper::prove(bn128_proof).map_err(|e| anyhow::anyhow!("SA Groth16: {e}"))?;
		// proof_to_solidity_json borrows slices; verify consumes Vecs — call in this order.
		let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)
			.map_err(|e| anyhow::anyhow!("SA solidity JSON: {e}"))?;
		Groth16Wrapper::verify(g16_proof, g16_pub_inp)
			.map_err(|e| anyhow::anyhow!("SA Groth16 verify: {e}"))?;

		parse_solidity_proof_json(&solidity_json)
	}

	/// Combined: prove_plonky2 + wrap_groth16 (convenience for production).
	pub fn prove(
		&self,
		nc: ProofNative,
		nn: ProofNative,
		ac: ProofNative,
		an: ProofNative,
		tx_agg: ProofNative,
	) -> Result<(SolidityProof, [u8; 32])> {
		let (root_proof, commitment) = self.prove_plonky2(nc, nn, ac, an, tx_agg)?;
		let solidity_proof = self.wrap_groth16(root_proof)?;
		Ok((solidity_proof, commitment))
	}
}

/// Build a [`NodeProverPool`] for aggregation-tree node proving.
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

/// In-process prover runtime that processes [`ProveRequest`]s end-to-end.
///
/// Holds all circuit services required for a full batch proof:
/// - Four native tree provers (notes/accounts × commitment/nullifier)
/// - The TX-leaf aggregation pipeline (optional)
/// - The single [`SuperAggregatorService`] that performs the final Groth16 wrap
pub struct ProverRuntime {
	note_commitment_prover: CommitmentProverService,
	account_commitment_prover: CommitmentProverService,
	note_nullifier_prover: NullifierProverService,
	account_nullifier_prover: NullifierProverService,
	aggregator: Option<AssociatedInputAggregatorService>,
	super_aggregator: SuperAggregatorService,
}

impl ProverRuntime {
	/// Initialise the complete prover runtime.
	///
	/// Builds the four tree circuits in memory, loads the SuperAggregator
	/// artifacts (BN128 + Groth16 initialisation), and optionally loads the
	/// TX-leaf aggregator.
	///
	/// # Parameters
	/// - `note_batch_size`: leaf count for note-tree circuits.
	/// - `account_batch_size`: leaf count for account-tree circuits.
	/// - `super_aggregator_artifacts_path`: path to the SuperAggregator artifact directory.
	/// - `aggregator_artifacts_path`: when `Some`, loads the `GenericAggregator` for TX-leaf
	///   aggregation.
	/// - `aggregation_prover_urls`: remote aggregation-prover base URLs.
	/// - `aggregation_prover_timeout_secs`: per-request HTTP timeout for remote provers.
	///
	/// # Errors
	/// Propagates any init error from the sub-services (artifact loading, circuit build).
	///
	/// # Side effects
	/// Initialises the global Groth16 FFI singleton for the SuperAggregator circuit.
	/// Generates a canonical padding proof if the TX-leaf aggregator is configured.
	pub fn init(
		note_batch_size: usize,
		account_batch_size: usize,
		super_aggregator_artifacts_path: std::path::PathBuf,
		aggregator_artifacts_path: Option<std::path::PathBuf>,
		aggregation_prover_urls: Vec<String>,
		aggregation_prover_timeout_secs: u64,
	) -> Result<Self> {
		let note_commitment_prover = CommitmentProverService::init(note_batch_size)?;
		let account_commitment_prover = CommitmentProverService::init(account_batch_size)?;
		let note_nullifier_prover = NullifierProverService::init(note_batch_size)?;
		let account_nullifier_prover = NullifierProverService::init(account_batch_size)?;

		let super_aggregator =
			SuperAggregatorService::from_artifacts(&super_aggregator_artifacts_path)?;

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
			note_commitment_prover,
			account_commitment_prover,
			note_nullifier_prover,
			account_nullifier_prover,
			aggregator,
			super_aggregator,
		})
	}

	/// Build all TX leaf proofs and aggregate them.
	///
	/// For each account slot:
	/// - Real private TX slots (present in `tx_proofs_by_slot`): uses the client-supplied PrivTx
	///   proof.
	/// - Deposit/inactive slots: generates a dummy proof with AN/NN overrides matching the tree
	///   padding values (required for the SA's ungated multi-set equality).
	///
	/// Called from a `spawn_blocking` context; uses `Handle::current().block_on(...)` to drive
	/// the async aggregation pipeline.
	fn build_and_aggregate_tx_proofs(
		aggregator: &Option<AssociatedInputAggregatorService>,
		account_batch_size: usize,
		tx_proofs_by_slot: &std::collections::HashMap<usize, Vec<u8>>,
		an_sorted_leaves: &[[u8; 32]],
		nn_sorted_leaves: &[[u8; 32]],
		an_sort_perm: &[usize],
		nn_sort_perm: &[usize],
	) -> Result<ProofNative> {
		let Some(agg_service) = aggregator else {
			anyhow::bail!("no aggregator configured (set TESSERA_AGGREGATOR_ARTIFACTS_PATH)");
		};

		let notes_per_slot = tessera_client::NOTE_BATCH;

		// Build one TX leaf proof per account slot.
		let mut leaf_proofs = Vec::with_capacity(account_batch_size);
		for s in 0..account_batch_size {
			if let Some(inner_proof_bytes) = tx_proofs_by_slot.get(&s) {
				// Real private TX: use the client-supplied inner PrivTx proof.
				leaf_proofs.push(
					agg_service
						.prove_leaf(inner_proof_bytes)
						.map_err(|e| anyhow::anyhow!("prove_leaf slot {s} (real): {e}"))?,
				);
			} else {
				// Deposit or inactive slot: generate dummy proof with AN/NN matching tree padding.
				// Use the sort permutation to recover this slot's value in the sorted array.
				let override_an = bytes32_to_f4(&an_sorted_leaves[an_sort_perm[s]]);
				let override_nn: [[F; 4]; tessera_client::NOTE_BATCH] = core::array::from_fn(|j| {
					let nn_idx = s * notes_per_slot + j;
					bytes32_to_f4(&nn_sorted_leaves[nn_sort_perm[nn_idx]])
				});
				let dummy_bytes = agg_service
					.prove_dummy_leaf(s as u64, override_an, override_nn)
					.map_err(|e| anyhow::anyhow!("prove_dummy_leaf slot {s}: {e}"))?;

				// Diagnostic: verify dummy proof has is_real=0.
				let dummy_proof = ProofWithPublicInputs::<F, ConfigNative, D>::from_bytes(
					dummy_bytes.clone(),
					&agg_service.inner_circuit.common,
				)
				.map_err(|e| anyhow::anyhow!("dummy deser slot {s}: {e:?}"))?;
				let is_real_val = dummy_proof.public_inputs
					[tessera_trees::proof_aggregation::IS_REAL_OFFSET]
					.to_canonical_u64();
				if is_real_val != 0 {
					error!(
						s,
						is_real = is_real_val,
						n_pis = dummy_proof.public_inputs.len(),
						"DIAGNOSTIC: dummy proof has is_real != 0"
					);
				}

				leaf_proofs.push(dummy_bytes);
			}
		}

		// Pad to the aggregation tree leaf count with dummy proofs.
		let cfg = agg_service.aggregator.config();
		let n_leaves = cfg.arity.pow(cfg.depth as u32);
		anyhow::ensure!(
			leaf_proofs.len() <= n_leaves,
			"batch size ({}) exceeds aggregation tree leaf count ({})",
			leaf_proofs.len(),
			n_leaves
		);
		for s in leaf_proofs.len()..n_leaves {
			let override_an = bytes32_to_f4(&an_sorted_leaves[an_sort_perm[s]]);
			let override_nn: [[F; 4]; tessera_client::NOTE_BATCH] = core::array::from_fn(|j| {
				let nn_idx = s * notes_per_slot + j;
				bytes32_to_f4(&nn_sorted_leaves[nn_sort_perm[nn_idx]])
			});
			leaf_proofs.push(
				agg_service
					.prove_dummy_leaf(s as u64, override_an, override_nn)
					.map_err(|e| anyhow::anyhow!("prove_dummy_leaf padding slot {s}: {e}"))?,
			);
		}

		// Bridge the async session into the synchronous context.
		let root_proof = tokio::runtime::Handle::current()
			.block_on(agg_service.aggregate_bytes(&leaf_proofs))
			.map_err(|e| anyhow::anyhow!("TX aggregation: {e}"))?;

		Ok(root_proof)
	}

	/// Prove a single [`ProveRequest`] end-to-end, returning a [`ProveOutcome`].
	///
	/// Steps:
	/// 1. Prove each of the 4 tree circuits (native Plonky2).
	/// 2. Aggregate the 16 TX leaf proofs through the streaming pipeline.
	/// 3. Pass all 5 native proofs to [`SuperAggregatorService::prove`] for the single BN128 →
	///    Groth16 wrapping step.
	/// 4. Return `ProveOutcome::Success` or `ProveOutcome::Failure`.
	pub fn prove_request(&mut self, request: ProveRequest) -> ProveOutcome {
		let batch_id = request.batch_id;
		match self.try_prove_request(request) {
			Ok(outcome) => outcome,
			Err(e) => {
				error!(batch_id, error = %e, "prove request failed");
				ProveOutcome::Failure {
					batch_id,
					error: e.to_string(),
				}
			},
		}
	}

	/// Inner proving pipeline that uses `?` for error propagation.
	fn try_prove_request(&mut self, request: ProveRequest) -> Result<ProveOutcome> {
		let batch_id = request.batch_id;

		// Assert sorted nullifier arrays (sequencer must sort before submission).
		anyhow::ensure!(
			is_sorted_u256(&request.an_sorted_leaves),
			"prover entry: AN leaves not sorted"
		);
		anyhow::ensure!(
			is_sorted_u256(&request.nn_sorted_leaves),
			"prover entry: NN leaves not sorted"
		);

		// ── Early PI consistency guard ──────────────────────────────────
		// For every real TX slot, deserialize the proof and verify that its
		// PI-embedded AC and NC match the leaf arrays the sequencer sent.
		// AN/NN are sorted (not positional) so they are validated post-
		// aggregation via multi-set equality in validate_an/nn_offcircuit.
		// This catches AC/NC mismatches *before* any expensive proving work.
		let notes_per_slot = tessera_client::NOTE_BATCH;
		if let Some(agg_service) = &self.aggregator {
			for (&slot, proof_bytes) in &request.tx_proofs_by_slot {
				let proof = ProofWithPublicInputs::<F, ConfigNative, D>::from_bytes(
					proof_bytes.clone(),
					&agg_service.inner_circuit.common,
				)
				.map_err(|e| anyhow::anyhow!("prover entry: slot {slot} proof deser: {e:?}"))?;

				let pis = &proof.public_inputs;
				let ac_off = TX_DATA_OFFSET + 4;
				let nc_off = TX_DATA_OFFSET + 40;

				// AC: PI[ac_off..ac_off+4] vs ac_sorted_leaves[slot]
				let expected_ac = bytes32_to_f4(&request.ac_sorted_leaves[slot]);
				for k in 0..4 {
					anyhow::ensure!(
						pis[ac_off + k] == expected_ac[k],
						"prover entry: slot {slot} AC field {k} mismatch: \
						 proof_pi={} leaf_array={}",
						pis[ac_off + k].to_canonical_u64(),
						expected_ac[k].to_canonical_u64()
					);
				}

				// NC: PI[nc_off..nc_off+32] vs nc_sorted_leaves[slot*8+j]
				for j in 0..notes_per_slot {
					let expected_nc =
						bytes32_to_f4(&request.nc_sorted_leaves[slot * notes_per_slot + j]);
					for k in 0..4 {
						anyhow::ensure!(
							pis[nc_off + j * 4 + k] == expected_nc[k],
							"prover entry: slot {slot} NC note {j} field {k} mismatch: \
							 proof_pi={} leaf_array={}",
							pis[nc_off + j * 4 + k].to_canonical_u64(),
							expected_nc[k].to_canonical_u64()
						);
					}
				}
			}
			// Log slot map boundaries for debugging.
			let mut real_slot_indices: Vec<usize> =
				request.tx_proofs_by_slot.keys().copied().collect();
			real_slot_indices.sort();
			let max_real = real_slot_indices.last().copied();
			info!(
				batch_id,
				real_slots = request.tx_proofs_by_slot.len(),
				?max_real,
				"prover entry: all TX proof PIs match leaf arrays"
			);
		}

		// Extract new roots up-front (before the request fields are consumed).
		let notes_new_root = request.notes_commitment_proof.root_new;
		let nullifier_notes_new_root = request.notes_nullifier_proof.new_root;
		let accounts_new_root = request.accounts_commitment_proof.root_new;
		let nullifier_accounts_new_root = request.accounts_nullifier_proof.new_root;

		info!(batch_id, "proving notes commitment tree");
		let nc_proof = self
			.note_commitment_prover
			.prove(&request.notes_commitment_proof)
			.map_err(|e| anyhow::anyhow!("notes commitment tree prove: {e}"))?;

		info!(batch_id, "proving notes nullifier tree");
		let nn_proof = self
			.note_nullifier_prover
			.prove(&request.notes_nullifier_proof)
			.map_err(|e| anyhow::anyhow!("notes nullifier tree prove: {e}"))?;

		info!(batch_id, "proving accounts commitment tree");
		let ac_proof = self
			.account_commitment_prover
			.prove(&request.accounts_commitment_proof)
			.map_err(|e| anyhow::anyhow!("accounts commitment tree prove: {e}"))?;

		info!(batch_id, "proving accounts nullifier tree");
		let an_proof = self
			.account_nullifier_prover
			.prove(&request.accounts_nullifier_proof)
			.map_err(|e| anyhow::anyhow!("accounts nullifier tree prove: {e}"))?;

		info!(batch_id, "building and aggregating TX leaf proofs");
		let account_batch_size = request.ac_sorted_leaves.len();
		let n_real = request.tx_proofs_by_slot.len();
		let tx_agg_root = Self::build_and_aggregate_tx_proofs(
			&self.aggregator,
			account_batch_size,
			&request.tx_proofs_by_slot,
			&request.an_sorted_leaves,
			&request.nn_sorted_leaves,
			&request.an_sort_perm,
			&request.nn_sort_perm,
		)
		.map_err(|e| anyhow::anyhow!("build_and_aggregate_tx_proofs: {e}"))?;

		// ── Off-circuit PI sanity checks ────────────────────────────────
		// These mirror the in-circuit constraints so that a mismatch is
		// caught with a human-readable message *before* the prover panics.
		info!(
			batch_id,
			n_real,
			ac_leaves = request.ac_sorted_leaves.len(),
			an_leaves = request.an_sorted_leaves.len(),
			"running off-circuit PI cross-checks"
		);
		let notes_per_slot = tessera_client::NOTE_BATCH;
		let tx_pis = &tx_agg_root.public_inputs;
		anyhow::ensure!(
			tx_pis.len() % TX_LEAF_PI_SIZE == 0,
			"TX aggregated proof has {} PIs, not a multiple of TX_LEAF_PI_SIZE ({})",
			tx_pis.len(),
			TX_LEAF_PI_SIZE,
		);
		let n_tx_slots = tx_pis.len() / TX_LEAF_PI_SIZE;
		anyhow::ensure!(
			n_tx_slots >= account_batch_size,
			"TX n_tx_slots ({}) < account_batch_size ({})",
			n_tx_slots,
			account_batch_size,
		);

		// Diagnostic: compare ac_sorted_leaves against tree proof PIs before off-circuit check.
		for s in 0..account_batch_size {
			let is_real_u64 = tx_pis[s * TX_LEAF_PI_SIZE + 2].to_canonical_u64();
			let in_map = request.tx_proofs_by_slot.contains_key(&s);
			let ac_from_tree = ac_proof.public_inputs[LEAF_OFFSET + s * 4].to_canonical_u64();
			let ac_from_tx = tx_pis[s * TX_LEAF_PI_SIZE + TX_DATA_OFFSET + 4].to_canonical_u64();
			let ac_from_leaf = bytes32_to_f4(&request.ac_sorted_leaves[s])[0].to_canonical_u64();
			if is_real_u64 == 1 && ac_from_tree != ac_from_tx {
				error!(
					batch_id,
					s,
					is_real = is_real_u64,
					in_map,
					ac_from_tree,
					ac_from_tx,
					ac_from_leaf,
					"DIAGNOSTIC: AC mismatch details"
				);
			}
		}

		validate_ac_offcircuit(&ac_proof.public_inputs, tx_pis, n_tx_slots)
			.map_err(|e| anyhow::anyhow!("off-circuit AC check: {e}"))?;
		validate_nc_offcircuit(&nc_proof.public_inputs, tx_pis, n_tx_slots, notes_per_slot)
			.map_err(|e| anyhow::anyhow!("off-circuit NC check: {e}"))?;
		validate_an_offcircuit(&an_proof.public_inputs, tx_pis, n_tx_slots)
			.map_err(|e| anyhow::anyhow!("off-circuit AN check: {e}"))?;
		validate_nn_offcircuit(&nn_proof.public_inputs, tx_pis, n_tx_slots, notes_per_slot)
			.map_err(|e| anyhow::anyhow!("off-circuit NN check: {e}"))?;
		info!(batch_id, "off-circuit PI cross-checks passed");

		info!(batch_id, "running SuperAggregator Plonky2 proof");
		log_super_pi_preimage_debug(batch_id, &nc_proof, &nn_proof, &ac_proof, &an_proof);
		let (sa_root_proof, super_pi_commitment) = self
			.super_aggregator
			.prove_plonky2(nc_proof, nn_proof, ac_proof, an_proof, tx_agg_root)
			.map_err(|e| anyhow::anyhow!("SuperAggregator plonky2: {e}"))?;

		info!(
			batch_id,
			super_pi_commitment = hex::encode(super_pi_commitment),
			"SuperAggregator Plonky2 done, wrapping (BN128 + Groth16)"
		);

		let solidity_proof = self
			.super_aggregator
			.wrap_groth16(sa_root_proof)
			.map_err(|e| anyhow::anyhow!("SuperAggregator groth16: {e}"))?;

		Ok(ProveOutcome::Success {
			batch_id,
			notes_new_root,
			nullifier_notes_new_root,
			accounts_new_root,
			nullifier_accounts_new_root,
			solidity_proof: Box::new(solidity_proof),
			super_pi_commitment,
		})
	}
}

/// Compute and log native per-tree Keccak sub-hashes of the SuperAggregator preimage.
///
/// Mirrors the circuit's Keccak computation over the reordered PI vectors.
/// Compare the logged `nc_hash`/`nn_hash`/`ac_hash`/`an_hash` against the on-chain
/// `SuperPiDebug` event to identify which tree's preimage diverges.
fn log_super_pi_preimage_debug(
	batch_id: u64,
	nc: &ProofNative,
	nn: &ProofNative,
	ac: &ProofNative,
	an: &ProofNative,
) {
	fn fields_to_bytes(pis: &[F]) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(pis.len() * 8);
		for f in pis {
			let v = f.to_canonical_u64();
			bytes.extend_from_slice(&((v >> 32) as u32).to_be_bytes());
			bytes.extend_from_slice(&((v & 0xFFFF_FFFF) as u32).to_be_bytes());
		}
		bytes
	}

	let nc_bytes = fields_to_bytes(&nc.public_inputs);
	let nn_bytes = fields_to_bytes(&nn.public_inputs);
	let ac_bytes = fields_to_bytes(&ac.public_inputs);
	let an_bytes = fields_to_bytes(&an.public_inputs);

	let nc_hash = hex::encode(alloy::primitives::keccak256(&nc_bytes));
	let nn_hash = hex::encode(alloy::primitives::keccak256(&nn_bytes));
	let ac_hash = hex::encode(alloy::primitives::keccak256(&ac_bytes));
	let an_hash = hex::encode(alloy::primitives::keccak256(&an_bytes));

	let full: Vec<u8> = nc_bytes
		.iter()
		.chain(nn_bytes.iter())
		.chain(ac_bytes.iter())
		.chain(an_bytes.iter())
		.copied()
		.collect();
	let full_hash = hex::encode(alloy::primitives::keccak256(&full));

	info!(
		batch_id,
		nc_hash,
		nn_hash,
		ac_hash,
		an_hash,
		full_hash,
		"native Keccak preimage sub-hashes (compare with on-chain SuperPiDebug event)"
	);
}

/// Convert a 32-byte tree leaf to 4 Goldilocks field elements.
///
/// Each 8-byte big-endian chunk becomes one field element, matching
/// `contract::bytes32_to_hash` but returning a plain `[F; 4]` array
/// suitable for the PrivTx override interface.
fn bytes32_to_f4(b: &[u8; 32]) -> [F; 4] {
	use plonky2::field::types::Field;
	core::array::from_fn(|i| {
		let val = u64::from_be_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
		F::from_canonical_u64(val)
	})
}

/// Parse the Groth16 JSON output produced by [`Groth16Wrapper::proof_to_solidity_json`]
/// into a [`SolidityProof`].
///
/// Expected JSON structure (all values hex strings with optional `0x` prefix):
/// ```json
/// { "proof": ["0x...", ...8 elements...],
///   "commitments": ["0x...", "0x..."],
///   "commitmentPok": ["0x...", "0x..."] }
/// ```
///
/// # Errors
/// Returns `Err` if the JSON is malformed, any key is missing, any value is not a valid
/// hex U256, or an array has the wrong number of elements (8, 2, 2).
pub(crate) fn parse_solidity_proof_json(json: &str) -> Result<SolidityProof> {
	let v: serde_json::Value = serde_json::from_str(json)?;

	let parse_u256_array = |key: &str, len: usize| -> Result<Vec<alloy::primitives::U256>> {
		let arr = v[key]
			.as_array()
			.ok_or_else(|| anyhow::anyhow!("missing {key}"))?;
		arr.iter()
			.take(len)
			.map(|s| {
				let hex_str = s
					.as_str()
					.ok_or_else(|| anyhow::anyhow!("expected string in {key}"))?;
				let hex_str = hex_str.trim_start_matches("0x");
				Ok(alloy::primitives::U256::from_str_radix(hex_str, 16)?)
			})
			.collect()
	};

	let proof_vec = parse_u256_array("proof", 8)?;
	let comm_vec = parse_u256_array("commitments", 2)?;
	let pok_vec = parse_u256_array("commitmentPok", 2)?;

	Ok(SolidityProof {
		proof: proof_vec
			.try_into()
			.map_err(|_| anyhow::anyhow!("proof: expected 8 elements"))?,
		commitments: comm_vec
			.try_into()
			.map_err(|_| anyhow::anyhow!("commitments: expected 2 elements"))?,
		commitment_pok: pok_vec
			.try_into()
			.map_err(|_| anyhow::anyhow!("commitmentPok: expected 2 elements"))?,
	})
}
