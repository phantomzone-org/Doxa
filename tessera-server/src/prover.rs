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
		hasher::Hash, BatchCommitmentProof, BatchCommitmentProofTargets, ChainedInsertProofTargets,
		NullifierChainedInsertProof,
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

const DUMMY_ASSOCIATED_INPUT_PROOF: &[u8] = &[0x01];

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
/// Mirrors [`CommitmentProverService`] but uses `ChainedInsertProofTargets`.
pub struct NullifierProverService {
	circuit_data: CircuitDataNative,
	targets: ChainedInsertProofTargets,
}

/// Aggregates `PrivateTx` leaf proofs into a single root Plonky2 proof using
/// the streaming aggregation pipeline.
///
/// Loaded from pre-built artifacts.  The root proof is passed to
/// [`SuperAggregatorService`] for the final BN128/Groth16 wrapping step.
pub struct AssociatedInputAggregatorService {
	aggregator: Arc<GenericAggregator<F, ConfigNative, D>>,
	pool: Arc<NodeProverPool<F, ConfigNative, D>>,
	/// Serialized canonical padding proof (73-PI leaf with is_real=false, all data zero).
	/// Replaces `DUMMY_ASSOCIATED_INPUT_PROOF` sentinels at padding positions before
	/// submitting to the aggregation pipeline.
	canonical_padding_proof: Vec<u8>,
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
		let targets = ChainedInsertProofTargets::new::<F, D>(&mut builder, 32, batch_size);
		targets.connect::<Hash, F, D>(&mut builder);
		let circuit_data = builder.build::<ConfigNative>();
		info!(batch_size, "nullifier prover initialized");
		Ok(Self {
			circuit_data,
			targets,
		})
	}

	/// Generate a native Plonky2 proof for the given nullifier batch.
	pub fn prove(&self, batch_proof: &NullifierChainedInsertProof<Hash>) -> Result<ProofNative> {
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

		// Rebuild the 73-PI leaf circuit (is_real=false, all data zero) to produce
		// the canonical padding proof.  Replaces DUMMY sentinels at padding positions.
		let n_pi = aggregator.leaf_common().num_public_inputs;
		info!(
			n_pi,
			"generating canonical padding proof for dummy leaf circuit"
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
		let mut pw = PartialWitness::new();
		pw.set_bool_target(is_real_t, false)?;
		for &t in &data_targets {
			pw.set_target(t, F::ZERO)?;
		}
		let padding_proof = leaf_circuit.prove(pw)?;
		leaf_circuit.verify(padding_proof.clone())?;
		let canonical_padding_proof = padding_proof.to_bytes();
		info!(
			bytes = canonical_padding_proof.len(),
			"canonical padding proof ready"
		);

		Ok(Self {
			aggregator: Arc::new(aggregator),
			pool,
			canonical_padding_proof,
		})
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

	/// Aggregate associated input proofs (one per leaf) using the streaming pipeline.
	///
	/// `DUMMY_ASSOCIATED_INPUT_PROOF` sentinels at padding positions are
	/// expanded to the pre-generated `canonical_padding_proof` before
	/// submission so the aggregator always receives `expected_count` valid
	/// plonky2 proofs.
	///
	/// Called from a `spawn_blocking` context; uses `Handle::current().block_on(...)` to drive
	/// the async aggregation pipeline.
	fn aggregate_associated_input_proofs(
		aggregator: &Option<AssociatedInputAggregatorService>,
		associated_input_proofs: &[Vec<u8>],
	) -> Result<ProofNative> {
		let Some(agg_service) = aggregator else {
			anyhow::bail!("no aggregator configured (set TESSERA_AGGREGATOR_ARTIFACTS_PATH)");
		};

		// Replace DUMMY sentinels with the canonical all-zero padding proof.
		let mut expanded: Vec<Vec<u8>> = associated_input_proofs
			.iter()
			.map(|p| {
				if p.as_slice() == DUMMY_ASSOCIATED_INPUT_PROOF {
					agg_service.canonical_padding_proof.clone()
				} else {
					p.clone()
				}
			})
			.collect();

		// Pad to the aggregation tree leaf count.
		let cfg = agg_service.aggregator.config();
		let n_leaves = cfg.arity.pow(cfg.depth as u32);
		anyhow::ensure!(
			expanded.len() <= n_leaves,
			"batch size ({}) exceeds aggregation tree leaf count ({})",
			expanded.len(),
			n_leaves
		);
		expanded.resize(n_leaves, agg_service.canonical_padding_proof.clone());

		// Bridge the async session into the synchronous context.
		let root_proof =
			tokio::runtime::Handle::current().block_on(agg_service.aggregate_bytes(&expanded))?;

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
	///
	/// # Side effects
	/// Drives the async aggregation pipeline via `Handle::current().block_on(...)`.
	pub fn prove_request(&mut self, request: ProveRequest) -> ProveOutcome {
		let batch_id = request.batch_id;

		// Extract new roots up-front (before the request fields are consumed).
		let notes_new_root = request.notes_commitment_proof.root_new;
		let nullifier_notes_new_root = match request.notes_nullifier_proof.proofs.last() {
			Some(p) => p.new_root,
			None => {
				return ProveOutcome::Failure {
					batch_id,
					error: "notes nullifier proof contains no insertions".to_string(),
				};
			},
		};
		let accounts_new_root = request.accounts_commitment_proof.root_new;
		let nullifier_accounts_new_root = match request.accounts_nullifier_proof.proofs.last() {
			Some(p) => p.new_root,
			None => {
				return ProveOutcome::Failure {
					batch_id,
					error: "accounts nullifier proof contains no insertions".to_string(),
				};
			},
		};

		// a. Notes commitment tree
		info!(batch_id, "proving notes commitment tree");
		let nc_proof = match self
			.note_commitment_prover
			.prove(&request.notes_commitment_proof)
		{
			Ok(p) => p,
			Err(e) => {
				error!("notes commitment proof failed: {e}");
				return ProveOutcome::Failure {
					batch_id,
					error: e.to_string(),
				};
			},
		};

		// b. Notes nullifier tree
		info!(batch_id, "proving notes nullifier tree");
		let nn_proof = match self
			.note_nullifier_prover
			.prove(&request.notes_nullifier_proof)
		{
			Ok(p) => p,
			Err(e) => {
				error!("notes nullifier proof failed: {e}");
				return ProveOutcome::Failure {
					batch_id,
					error: e.to_string(),
				};
			},
		};

		// c. Accounts commitment tree
		info!(batch_id, "proving accounts commitment tree");
		let ac_proof = match self
			.account_commitment_prover
			.prove(&request.accounts_commitment_proof)
		{
			Ok(p) => p,
			Err(e) => {
				error!("accounts commitment proof failed: {e}");
				return ProveOutcome::Failure {
					batch_id,
					error: e.to_string(),
				};
			},
		};

		// d. Accounts nullifier tree
		info!(batch_id, "proving accounts nullifier tree");
		let an_proof = match self
			.account_nullifier_prover
			.prove(&request.accounts_nullifier_proof)
		{
			Ok(p) => p,
			Err(e) => {
				error!("accounts nullifier proof failed: {e}");
				return ProveOutcome::Failure {
					batch_id,
					error: e.to_string(),
				};
			},
		};

		// e. Aggregate 16 TX leaf proofs → single native root proof
		info!(batch_id, "aggregating TX leaf proofs");
		let tx_agg_root = match Self::aggregate_associated_input_proofs(
			&self.aggregator,
			&request.associated_tx_proofs,
		) {
			Ok(p) => p,
			Err(e) => {
				error!("TX leaf aggregation failed: {e}");
				return ProveOutcome::Failure {
					batch_id,
					error: e.to_string(),
				};
			},
		};

		// f. SuperAggregator: combines all 5 proofs → BN128 → Groth16
		info!(batch_id, "running SuperAggregator (BN128 + Groth16)");
		log_super_pi_preimage_debug(batch_id, &nc_proof, &nn_proof, &ac_proof, &an_proof);
		match self
			.super_aggregator
			.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_agg_root)
		{
			Ok((solidity_proof, super_pi_commitment)) => {
				info!(
					batch_id,
					super_pi_commitment = hex::encode(super_pi_commitment),
					"SuperAggregator commitment (compare with on-chain TransactionBatchRegistered.superPiCommitment)"
				);
				ProveOutcome::Success {
					batch_id,
					notes_new_root,
					nullifier_notes_new_root,
					accounts_new_root,
					nullifier_accounts_new_root,
					solidity_proof: Box::new(solidity_proof),
					super_pi_commitment,
				}
			},
			Err(e) => {
				error!("SuperAggregator prove failed: {e}");
				ProveOutcome::Failure {
					batch_id,
					error: e.to_string(),
				}
			},
		}
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

	let nn_len = nn.public_inputs.len();
	let an_len = an.public_inputs.len();
	let nn_nrs = nn_len - 8; // new_root at second-to-last group of 4
	let an_nrs = an_len - 8;

	let nc_bytes = fields_to_bytes(&nc.public_inputs);
	let nn_pis: Vec<F> = nn.public_inputs[..4]
		.iter()
		.chain(nn.public_inputs[nn_nrs..nn_nrs + 4].iter())
		.chain(nn.public_inputs[5..nn_nrs].iter())
		.chain(nn.public_inputs[nn_nrs + 4..].iter())
		.copied()
		.collect();
	let nn_bytes = fields_to_bytes(&nn_pis);
	let ac_bytes = fields_to_bytes(&ac.public_inputs);
	let an_pis: Vec<F> = an.public_inputs[..4]
		.iter()
		.chain(an.public_inputs[an_nrs..an_nrs + 4].iter())
		.chain(an.public_inputs[5..an_nrs].iter())
		.chain(an.public_inputs[an_nrs + 4..].iter())
		.copied()
		.collect();
	let an_bytes = fields_to_bytes(&an_pis);

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
