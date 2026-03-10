use std::{path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use plonky2::{
	field::types::{Field, PrimeField64},
	iop::{
		target::Target,
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use tessera_trees::{
	groth::{BN128Wrapper, Groth16Wrapper},
	proof_aggregation::{GenericAggregator, SuperAggregator},
	tree::{
		hasher::Hash, BatchCommitmentProof, BatchCommitmentProofTargets, BatchInsertProof,
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
	types::{ProveOutcome, ProveRequest, SolidityProof},
};

/// Encapsulates the commitment-tree proof pipeline (notes or accounts).
///
/// Holds the compiled plonky2 circuit and its public-input targets.
/// Produces a raw Plonky2 proof; wrapping is handled centrally by
/// [`SuperAggregatorService`].
pub struct CommitmentProverService {
	circuit_data: CircuitDataNative,
	targets: BatchCommitmentProofTargets,
}

/// Encapsulates the nullifier-tree proof pipeline (notes or accounts).
///
/// Mirrors [`CommitmentProverService`] but uses `BatchNullifierInsertProofTargets`.
pub struct NullifierProverService {
	circuit_data: CircuitDataNative,
	targets: BatchNullifierInsertProofTargets,
}

/// Aggregates `PrivateTx` leaf proofs into a single root Plonky2 proof using
/// the streaming aggregation pipeline.
///
/// Loaded from pre-built artifacts.  The root proof is passed to
/// [`SuperAggregatorService`] for the final BN128/Groth16 wrapping step.
pub struct AssociatedInputAggregatorService {
	aggregator: Arc<GenericAggregator<F, ConfigNative, D>>,
	pool: Arc<NodeProverPool<F, ConfigNative, D>>,
	/// The trivial TX leaf circuit (73 PIs, no constraints).
	leaf_circuit: CircuitDataNative,
	/// Witness target for `is_real` (PI[0]).
	is_real_target: plonky2::iop::target::BoolTarget,
	/// Witness targets for the 72 data fields (PI[1..73]).
	data_targets: Vec<Target>,
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
		let targets = BatchCommitmentProofTargets::new::<F, D>(&mut builder, 32, batch_size);
		targets.connect::<Hash, F, D>(&mut builder);
		let circuit_data = builder.build::<ConfigNative>();
		info!(batch_size, "commitment prover initialized");
		Ok(Self {
			circuit_data,
			targets,
		})
	}

	/// Generate a native Plonky2 proof for the given commitment batch.
	pub fn prove(&self, batch_proof: &BatchCommitmentProof<Hash>) -> Result<ProofNative> {
		let mut pw = PartialWitness::new();
		self.targets.set::<Hash, F, 32>(&mut pw, batch_proof)?;
		let proof = self.circuit_data.prove(pw)?;
		self.circuit_data.verify(proof.clone())?;
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
		let targets = BatchNullifierInsertProofTargets::new::<F, D>(&mut builder, 32, batch_size);
		targets.connect::<Hash, F, D>(&mut builder);
		let circuit_data = builder.build::<ConfigNative>();
		info!(batch_size, "nullifier prover initialized");
		Ok(Self {
			circuit_data,
			targets,
		})
	}

	/// Generate a native Plonky2 proof for the given nullifier batch.
	pub fn prove(&self, batch_proof: &BatchInsertProof<Hash>) -> Result<ProofNative> {
		let mut pw = PartialWitness::new();
		self.targets.set::<Hash, F, 32>(&mut pw, batch_proof)?;
		let proof = self.circuit_data.prove(pw)?;
		self.circuit_data.verify(proof.clone())?;
		Ok(proof)
	}
}

impl AssociatedInputAggregatorService {
	/// Load from pre-built aggregator artifacts at `path`, using `pool` for
	/// distributed node proving.
	///
	/// Expects the standard layout produced by `cargo run --bin aggregator_artifacts --release`:
	/// native Plonky2 aggregator data directly under `path`.
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
		let aggregator = GenericAggregator::<F, ConfigNative, D>::from_artifacts(path)?;

		// Rebuild the 73-PI leaf circuit (no constraints) so that we can prove
		// arbitrary TX leaf values at proving time.
		let n_pi = aggregator.leaf_common().num_public_inputs;
		info!(
			n_pi,
			"building TX leaf circuit for dynamic proof generation"
		);
		let leaf_config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(leaf_config);
		let is_real_t = builder.add_virtual_bool_target_safe();
		builder.register_public_input(is_real_t.target);
		let data_targets: Vec<Target> = (0..n_pi - 1)
			.map(|_| builder.add_virtual_target())
			.collect();
		for &t in &data_targets {
			builder.register_public_input(t);
		}
		let leaf_circuit = builder.build::<ConfigNative>();
		info!("TX leaf circuit ready");

		Ok(Self {
			aggregator: Arc::new(aggregator),
			pool,
			leaf_circuit,
			is_real_target: is_real_t,
			data_targets,
		})
	}

	/// Prove a single TX leaf with the given `is_real` flag and 72 data fields.
	///
	/// The leaf circuit is trivial (no constraints), so proving is fast.
	fn prove_leaf(&self, is_real: bool, data: &[F]) -> Result<Vec<u8>> {
		anyhow::ensure!(
			data.len() == self.data_targets.len(),
			"TX leaf data length mismatch: got {}, expected {}",
			data.len(),
			self.data_targets.len()
		);
		let mut pw = PartialWitness::new();
		pw.set_bool_target(self.is_real_target, is_real)?;
		for (&t, &v) in self.data_targets.iter().zip(data.iter()) {
			pw.set_target(t, v)?;
		}
		let proof = self.leaf_circuit.prove(pw)?;
		Ok(proof.to_bytes())
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

	/// Prove: verifies all 5 inner proofs in the SuperAggregator circuit, then
	/// wraps the root proof through BN128 → Groth16.
	///
	/// Returns `(solidity_proof, super_pi_commitment)` where
	/// `super_pi_commitment` is the 32-byte Keccak digest packed from the
	/// root proof's 8 public inputs (one u32 word each, big-endian).
	pub fn prove(
		&self,
		nc: ProofNative,
		nn: ProofNative,
		ac: ProofNative,
		an: ProofNative,
		tx_agg: ProofNative,
	) -> Result<(SolidityProof, [u8; 32])> {
		info!("running SuperAggregator circuit");
		let root_proof = self.super_agg.prove(nc, nn, ac, an, tx_agg)?;

		// Extract super_pi_commitment: 8 public inputs, each a u32 word (big-endian).
		let super_pi_commitment = {
			let pis = &root_proof.public_inputs;
			anyhow::ensure!(
				pis.len() == 8,
				"SuperAggregator root must have exactly 8 public inputs, got {}",
				pis.len()
			);
			let mut bytes = [0u8; 32];
			for (i, fi) in pis.iter().enumerate() {
				let word = fi.to_canonical_u64() as u32;
				bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
			}
			bytes
		};

		info!("BN128-wrapping SuperAggregator root proof");
		let bn128_proof = self.bn128_wrapper.wrap_proof_to_bn128(root_proof)?;

		info!("Groth16-proving SuperAggregator");
		let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(bn128_proof)?;
		// proof_to_solidity_json borrows slices; verify consumes Vecs — call in this order.
		let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
		Groth16Wrapper::verify(g16_proof, g16_pub_inp)?;
		let solidity_proof = parse_solidity_proof_json(&solidity_json)?;
		Ok((solidity_proof, super_pi_commitment))
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

	/// Build all TX leaf proofs from sorted tree data, then aggregate them.
	///
	/// Each TX leaf proof carries the sorted tree leaf values for its slot
	/// (real or dummy).  `is_real` is set to `true` only for slots listed in
	/// `real_account_slots`.
	///
	/// Called from a `spawn_blocking` context; uses `Handle::current().block_on(...)` to drive
	/// the async aggregation pipeline.
	#[allow(clippy::too_many_arguments)]
	fn build_and_aggregate_tx_proofs(
		aggregator: &Option<AssociatedInputAggregatorService>,
		nc_sorted: &[Hash],
		nn_sorted: &[Hash],
		ac_sorted: &[Hash],
		an_sorted: &[Hash],
		real_account_slots: &[usize],
		account_batch_size: usize,
		notes_per_slot: usize,
	) -> Result<ProofNative> {
		let Some(agg_service) = aggregator else {
			anyhow::bail!("no aggregator configured (set TESSERA_AGGREGATOR_ARTIFACTS_PATH)");
		};

		anyhow::ensure!(
			nn_sorted.len() == account_batch_size * notes_per_slot,
			"NN sorted leaves: got {}, expected {}",
			nn_sorted.len(),
			account_batch_size * notes_per_slot
		);
		anyhow::ensure!(
			nc_sorted.len() == account_batch_size * notes_per_slot,
			"NC sorted leaves: got {}, expected {}",
			nc_sorted.len(),
			account_batch_size * notes_per_slot
		);
		anyhow::ensure!(an_sorted.len() == account_batch_size);
		anyhow::ensure!(ac_sorted.len() == account_batch_size);

		// Build one TX leaf proof per account slot.
		let mut leaf_proofs = Vec::with_capacity(account_batch_size);
		for s in 0..account_batch_size {
			let is_real = real_account_slots.contains(&s);
			let mut data = Vec::with_capacity(72);
			// note nullifiers (8 × 4 fields) — from NN
			for j in 0..notes_per_slot {
				let leaf_idx = s * notes_per_slot + j;
				data.extend_from_slice(&nn_sorted[leaf_idx].0);
			}
			// note commitments (8 × 4 fields) — from NC
			for j in 0..notes_per_slot {
				let leaf_idx = s * notes_per_slot + j;
				data.extend_from_slice(&nc_sorted[leaf_idx].0);
			}
			// account nullifier (1 × 4 fields) — from AN
			data.extend_from_slice(&an_sorted[s].0);
			// account commitment (1 × 4 fields) — from AC
			data.extend_from_slice(&ac_sorted[s].0);

			leaf_proofs.push(agg_service.prove_leaf(is_real, &data)?);
		}

		// Pad to the aggregation tree leaf count with all-zero padding proofs.
		let cfg = agg_service.aggregator.config();
		let n_leaves = cfg.arity.pow(cfg.depth as u32);
		anyhow::ensure!(
			leaf_proofs.len() <= n_leaves,
			"batch size ({}) exceeds aggregation tree leaf count ({})",
			leaf_proofs.len(),
			n_leaves
		);
		let padding_proof = agg_service.prove_leaf(false, &vec![F::ZERO; 72])?;
		leaf_proofs.resize(n_leaves, padding_proof);

		// Bridge the async session into the synchronous context.
		let root_proof = tokio::runtime::Handle::current()
			.block_on(agg_service.aggregate_bytes(&leaf_proofs))?;

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

		// Extract new roots up-front (before the request fields are consumed).
		let notes_new_root = request.notes_commitment_proof.root_new;
		let nullifier_notes_new_root = request.notes_nullifier_proof.new_root;
		let accounts_new_root = request.accounts_commitment_proof.root_new;
		let nullifier_accounts_new_root = request.accounts_nullifier_proof.new_root;

		info!(batch_id, "proving notes commitment tree");
		let nc_proof = self
			.note_commitment_prover
			.prove(&request.notes_commitment_proof)?;

		info!(batch_id, "proving notes nullifier tree");
		let nn_proof = self
			.note_nullifier_prover
			.prove(&request.notes_nullifier_proof)?;

		info!(batch_id, "proving accounts commitment tree");
		let ac_proof = self
			.account_commitment_prover
			.prove(&request.accounts_commitment_proof)?;

		info!(batch_id, "proving accounts nullifier tree");
		let an_proof = self
			.account_nullifier_prover
			.prove(&request.accounts_nullifier_proof)?;

		info!(
			batch_id,
			"building and aggregating TX leaf proofs from sorted data"
		);
		let nc_sorted_hashes = crate::contract::bytes_slice_to_hashes(&request.nc_sorted_leaves)?;
		let nn_sorted_hashes = crate::contract::bytes_slice_to_hashes(&request.nn_sorted_leaves)?;
		let ac_sorted_hashes = crate::contract::bytes_slice_to_hashes(&request.ac_sorted_leaves)?;
		let an_sorted_hashes = crate::contract::bytes_slice_to_hashes(&request.an_sorted_leaves)?;
		let account_batch_size = request.ac_sorted_leaves.len();
		let notes_per_slot = if account_batch_size > 0 {
			request.nc_sorted_leaves.len() / account_batch_size
		} else {
			8
		};
		let tx_agg_root = Self::build_and_aggregate_tx_proofs(
			&self.aggregator,
			&nc_sorted_hashes,
			&nn_sorted_hashes,
			&ac_sorted_hashes,
			&an_sorted_hashes,
			&request.real_account_slots,
			account_batch_size,
			notes_per_slot,
		)?;

		info!(batch_id, "running SuperAggregator (BN128 + Groth16)");
		log_super_pi_preimage_debug(batch_id, &nc_proof, &nn_proof, &ac_proof, &an_proof);
		let (solidity_proof, super_pi_commitment) =
			self.super_aggregator
				.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_agg_root)?;

		info!(
			batch_id,
			super_pi_commitment = hex::encode(super_pi_commitment),
			"SuperAggregator done"
		);

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
fn parse_solidity_proof_json(json: &str) -> Result<SolidityProof> {
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
