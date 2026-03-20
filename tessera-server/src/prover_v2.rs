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

use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use plonky2::{field::types::PrimeField64, plonk::proof::ProofWithPublicInputs};
use tessera_utils::{
	groth::{BN128Wrapper, Groth16Wrapper},
	hasher::HashOutput,
	ConfigNative, ProofNative, D, F,
};
use tracing::{error, info};

use crate::{
	aggregation_pipeline::{
		start_aggregation_session, AsyncNodeProver, LocalAsyncNodeProver, NodeProverPool,
		RemoteNodeProver,
	},
	proof_aggregation::{
		validate_deposit_subtree_nc_offcircuit, validate_subtree_nc_offcircuit,
		DepositSuperAggregatorV2, GenericAggregator, SubtreeRootCircuit, SuperAggregatorV2,
		DEPOSIT_LEAF_PI_SIZE, TX_LEAF_PI_SIZE,
	},
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
	/// `batch_size` must match the size the circuit was built for (= priv_tx_batch_size ×
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
		root: HashOutput,
		main_pool_cfg_root: [u8; 32],
	) -> Result<(ProofNative, [u8; 32])> {
		let root_proof = self
			.super_agg
			.prove(tx_agg, sr, root, main_pool_cfg_root)
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
// DepositSuperAggregatorV2Service
// ---------------------------------------------------------------------------

/// Wraps [`DepositSuperAggregatorV2`] + BN128 + labeled Groth16 for deposit proving.
pub struct DepositSuperAggregatorV2Service {
	deposit_agg: DepositSuperAggregatorV2,
	bn128_wrapper: BN128Wrapper,
}

impl DepositSuperAggregatorV2Service {
	/// Load from pre-built artifacts at `path`.
	///
	/// Also loads the BN128 wrapper and initialises the `"deposit"` Groth16 instance.
	pub fn from_artifacts(path: &Path) -> Result<Self> {
		if !DepositSuperAggregatorV2::has_artifacts(path) {
			return Err(anyhow::anyhow!(
				"DepositSuperAggregatorV2 artifacts not found at {:?}. \
				 Run `cargo run --bin deposit_tx_artifacts --release` first.",
				path
			));
		}
		info!("loading DepositSuperAggregatorV2 from artifacts");
		let deposit_agg = DepositSuperAggregatorV2::from_artifacts(path)?;

		let plonky2_path = path.join("plonky2-proof");
		let groth16_artifacts_path = path.join("groth-artifacts");

		if !BN128Wrapper::has_full_artifacts(&plonky2_path) {
			return Err(anyhow::anyhow!(
				"BN128 wrapper artifacts not found at {:?}. \
				 Run `cargo run --bin deposit_tx_artifacts --release` first.",
				plonky2_path
			));
		}
		info!("loading BN128 wrapper (DepositSuperAggregatorV2) from artifacts");
		let bn128_wrapper = BN128Wrapper::from_artifacts(&plonky2_path)?;

		info!("initialising Groth16 \"deposit\" instance");
		Groth16Wrapper::init_with_label("deposit", &plonky2_path, &groth16_artifacts_path)?;
		Groth16Wrapper::check_init_with_label("deposit");

		Ok(Self {
			deposit_agg,
			bn128_wrapper,
		})
	}

	/// Number of deposit-TX slots the DSAV2 circuit was built for.
	pub fn deposit_batch_size(&self) -> usize {
		self.deposit_agg.deposit_batch_size()
	}

	/// Stage 1: DSAV2 Plonky2 proof (deposit agg + SR → piCommitment).
	pub fn prove_plonky2(
		&self,
		deposit_agg: ProofNative,
		sr: ProofNative,
		act_root: tessera_utils::hasher::HashOutput,
		main_pool_cfg_root: [u8; 32],
	) -> Result<(ProofNative, [u8; 32])> {
		let root_proof = self
			.deposit_agg
			.prove(deposit_agg, sr, act_root, main_pool_cfg_root)
			.map_err(|e| anyhow::anyhow!("DSAV2 plonky2 prove: {e}"))?;

		let pis = &root_proof.public_inputs;
		anyhow::ensure!(
			pis.len() == 8,
			"DSAV2 root must have exactly 8 public inputs, got {}",
			pis.len()
		);
		let mut commitment = [0u8; 32];
		for (i, fi) in pis.iter().enumerate() {
			let word = fi.to_canonical_u64() as u32;
			commitment[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
		}
		Ok((root_proof, commitment))
	}

	/// Stage 2: BN128 wrap + Groth16 prove (labeled "deposit").
	pub fn wrap_groth16(&self, root_proof: ProofNative) -> Result<SolidityProof> {
		let bn128_proof = self
			.bn128_wrapper
			.wrap_proof_to_bn128(root_proof)
			.map_err(|e| anyhow::anyhow!("DSAV2 BN128 wrap: {e}"))?;

		let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove_with_label("deposit", bn128_proof)
			.map_err(|e| anyhow::anyhow!("DSAV2 Groth16: {e}"))?;
		let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)
			.map_err(|e| anyhow::anyhow!("DSAV2 solidity JSON: {e}"))?;
		Groth16Wrapper::verify_with_label("deposit", g16_proof, g16_pub_inp)
			.map_err(|e| anyhow::anyhow!("DSAV2 Groth16 verify: {e}"))?;
		parse_solidity_proof_json(&solidity_json)
	}
}

// ---------------------------------------------------------------------------
// DepositAggregatorService
// ---------------------------------------------------------------------------

/// Aggregates deposit-TX leaf proofs into a single root proof.
pub struct DepositAggregatorService {
	aggregator: Arc<GenericAggregator<F, ConfigNative, D>>,
	pool: Arc<NodeProverPool<F, ConfigNative, D>>,
	/// Inner deposit-TX circuit data (needed for proof deserialization).
	pub(crate) inner_circuit: tessera_utils::CircuitDataNative,
}

impl DepositAggregatorService {
	/// Load from pre-built aggregator artifacts at `path`.
	pub fn from_artifacts_and_pool(
		path: &Path,
		pool: Arc<NodeProverPool<F, ConfigNative, D>>,
	) -> Result<Self> {
		if !GenericAggregator::<F, ConfigNative, D>::has_full_artifacts(path)? {
			return Err(anyhow::anyhow!(
				"deposit aggregator artifacts not found at {:?}. \
				 Run `cargo run --bin deposit_tx_artifacts --release` first.",
				path
			));
		}
		info!("loading deposit-TX aggregator from artifacts");
		let aggregator = GenericAggregator::<F, ConfigNative, D>::from_artifacts(
			path,
			&tessera_client::TesseraGateSerializer,
		)?;

		info!("building inner deposit-TX circuit for proof deserialization");
		let inner_circuit = tessera_client::build_deposit_tx_circuit().circuit_data;
		info!(
			inner_pi = inner_circuit.common.num_public_inputs,
			inner_degree_bits = inner_circuit.common.degree_bits(),
			"inner deposit-TX circuit ready"
		);

		Ok(Self {
			aggregator: Arc::new(aggregator),
			pool,
			inner_circuit,
		})
	}

	/// Total leaf count of the aggregation tree.
	pub(crate) fn n_leaves(&self) -> usize {
		let cfg = self.aggregator.config();
		cfg.arity.pow(cfg.depth as u32)
	}

	/// Submit all leaf proof bytes and await the root proof.
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

// ---------------------------------------------------------------------------
// DepositPipelineConfig
// ---------------------------------------------------------------------------

/// Artifact paths for the optional deposit proving pipeline.
pub struct DepositPipelineConfig {
	/// `deposit-tx-aggregator/` artifact directory.
	pub deposit_tx_aggregator_path: std::path::PathBuf,
	/// `deposit-subtree-root/` artifact directory.
	pub deposit_subtree_root_path: std::path::PathBuf,
	/// `deposit-super-aggregator-v2/` artifact directory.
	pub deposit_super_aggregator_path: std::path::PathBuf,
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
/// Optionally also holds the deposit pipeline (loaded via [`DepositPipelineConfig`]).
pub struct ProverRuntimeV2 {
	subtree_root: SubtreeRootProverService,
	aggregator: Option<AssociatedInputAggregatorService>,
	super_aggregator: SuperAggregatorV2Service,
	/// Bytes of the pre-computed dummy inner TX proof (is_real=0).
	dummy_inner_proof_bytes: Vec<u8>,
	// Deposit pipeline (None when DepositPipelineConfig was not supplied to init).
	deposit_subtree_root: Option<SubtreeRootProverService>,
	deposit_aggregator: Option<DepositAggregatorService>,
	deposit_super_aggregator: Option<DepositSuperAggregatorV2Service>,
	/// Bytes of the pre-computed dummy inner deposit-TX proof (is_real=0).
	dummy_inner_deposit_proof_bytes: Option<Vec<u8>>,
}

impl ProverRuntimeV2 {
	/// Initialise the V2 prover runtime.
	///
	/// # Parameters
	/// - `sr_artifacts_path`: SubtreeRootCircuit artifact directory.
	/// - `sr_batch_size`: leaf count for the SubtreeRoot circuit (= priv_tx_batch_size ×
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
		deposit: Option<DepositPipelineConfig>,
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

		// Deposit pipeline (optional).
		let (deposit_subtree_root, deposit_aggregator, deposit_super_aggregator, dummy_deposit) =
			if let Some(cfg) = deposit {
				let dsav2 = DepositSuperAggregatorV2Service::from_artifacts(
					&cfg.deposit_super_aggregator_path,
				)?;
				let deposit_batch_size = dsav2.deposit_batch_size();

				let deposit_sr = SubtreeRootProverService::from_artifacts(
					&cfg.deposit_subtree_root_path,
					deposit_batch_size,
				)?;

				let deposit_pool = build_pool(
					Some(&cfg.deposit_tx_aggregator_path),
					&[], // no remote provers for deposit
					timeout,
				)?;
				let dep_agg = DepositAggregatorService::from_artifacts_and_pool(
					&cfg.deposit_tx_aggregator_path,
					deposit_pool,
				)?;

				let dummy_deposit_path = cfg
					.deposit_tx_aggregator_path
					.join("dummy_inner_deposit_proof.bin");
				let dummy_deposit_bytes = std::fs::read(&dummy_deposit_path).map_err(|e| {
					anyhow::anyhow!(
						"failed to read dummy_inner_deposit_proof.bin from {:?}: {e}",
						dummy_deposit_path
					)
				})?;
				info!(
					bytes = dummy_deposit_bytes.len(),
					"loaded dummy inner deposit proof"
				);

				(
					Some(deposit_sr),
					Some(dep_agg),
					Some(dsav2),
					Some(dummy_deposit_bytes),
				)
			} else {
				(None, None, None, None)
			};

		Ok(Self {
			subtree_root,
			aggregator,
			super_aggregator,
			dummy_inner_proof_bytes,
			deposit_subtree_root,
			deposit_aggregator,
			deposit_super_aggregator,
			dummy_inner_deposit_proof_bytes: dummy_deposit,
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

	/// Prove a single [`ConsumeProveRequest`] end-to-end via the deposit pipeline.
	pub fn prove_consume_request(&mut self, request: ConsumeProveRequest) -> ConsumeOutcome {
		let batch_id = request.batch_id;
		match self.try_prove_consume_request(request) {
			Ok(outcome) => outcome,
			Err(e) => {
				error!(batch_id, error = %e, "prove_consume_request failed");
				ConsumeOutcome::Failure {
					batch_id,
					error: e.to_string(),
				}
			},
		}
	}

	fn try_prove_consume_request(
		&mut self,
		request: ConsumeProveRequest,
	) -> Result<ConsumeOutcome> {
		let batch_id = request.batch_id;

		let deposit_aggregator = self
			.deposit_aggregator
			.as_ref()
			.ok_or_else(|| anyhow::anyhow!("deposit aggregator not loaded; supply DepositPipelineConfig to ProverRuntimeV2::init"))?;
		let deposit_sr = self
			.deposit_subtree_root
			.as_ref()
			.ok_or_else(|| anyhow::anyhow!("deposit SubtreeRoot circuit not loaded"))?;
		let deposit_super_agg = self
			.deposit_super_aggregator
			.as_ref()
			.ok_or_else(|| anyhow::anyhow!("DepositSuperAggregatorV2 not loaded"))?;
		let dummy_deposit_bytes = self
			.dummy_inner_deposit_proof_bytes
			.as_deref()
			.ok_or_else(|| anyhow::anyhow!("dummy deposit proof not loaded"))?;

		// ── 1. Build & aggregate deposit-TX leaf proofs ──────────────────────
		info!(batch_id, "building deposit-TX leaf proofs");
		let deposit_agg_proof = Self::build_and_aggregate_deposit_proofs(
			deposit_aggregator,
			&request.consume_proofs_by_slot,
			dummy_deposit_bytes,
		)?;

		// ── 2. Prove deposit SubtreeRootCircuit ──────────────────────────────
		let nc_hashes: Vec<HashOutput> = request.nc_leaves.iter().map(bytes32_to_hash).collect();
		info!(
			batch_id,
			sr_batch_size = nc_hashes.len(),
			"proving deposit SubtreeRootCircuit"
		);
		let sr_proof = deposit_sr
			.prove(&nc_hashes)
			.map_err(|e| anyhow::anyhow!("deposit SubtreeRootCircuit prove: {e}"))?;
		let batch_poseidon_root = SubtreeRootCircuit::root_from_proof(&sr_proof);

		// ── 3. Off-circuit cross-check (deposit NC in agg proof ↔ SR leaves) ─
		let n_deposit_slots = deposit_agg_proof.public_inputs.len() / DEPOSIT_LEAF_PI_SIZE;
		info!(
			batch_id,
			n_deposit_slots, "running deposit off-circuit NC cross-check"
		);
		validate_deposit_subtree_nc_offcircuit(
			&sr_proof.public_inputs,
			&deposit_agg_proof.public_inputs,
			n_deposit_slots,
		)
		.map_err(|e| anyhow::anyhow!("deposit off-circuit NC cross-check: {e}"))?;

		// ── 4. DSAV2 Plonky2 proof ───────────────────────────────────────────
		info!(batch_id, "running DepositSuperAggregatorV2 Plonky2 proof");
		let (dsav2_root_proof, super_pi_commitment) = deposit_super_agg
			.prove_plonky2(
				deposit_agg_proof,
				sr_proof,
				request.root,
				request.main_pool_cfg_root,
			)
			.map_err(|e| anyhow::anyhow!("DSAV2 plonky2: {e}"))?;

		info!(
			batch_id,
			super_pi_commitment = hex::encode(super_pi_commitment),
			"DSAV2 Plonky2 done, wrapping (BN128 + Groth16 deposit)"
		);

		// ── 5. BN128 + Groth16 wrap ──────────────────────────────────────────
		let solidity_proof = deposit_super_agg
			.wrap_groth16(dsav2_root_proof)
			.map_err(|e| anyhow::anyhow!("DSAV2 Groth16: {e}"))?;

		Ok(ConsumeOutcome::Success {
			batch_id,
			batch_poseidon_root,
			solidity_proof: Box::new(solidity_proof),
			super_pi_commitment,
		})
	}

	fn build_and_aggregate_deposit_proofs(
		deposit_aggregator: &DepositAggregatorService,
		consume_proofs_by_slot: &HashMap<usize, Vec<u8>>,
		dummy_proof_bytes: &[u8],
	) -> Result<ProofNative> {
		let n_leaves = deposit_aggregator.n_leaves();
		let mut leaf_proofs: Vec<Vec<u8>> = Vec::with_capacity(n_leaves);

		for s in 0..n_leaves {
			if let Some(proof_bytes) = consume_proofs_by_slot.get(&s) {
				ProofWithPublicInputs::<F, ConfigNative, D>::from_bytes(
					proof_bytes.clone(),
					&deposit_aggregator.inner_circuit.common,
				)
				.map_err(|e| anyhow::anyhow!("deposit slot {s} proof deser: {e:?}"))?;
				leaf_proofs.push(proof_bytes.clone());
			} else {
				leaf_proofs.push(dummy_proof_bytes.to_vec());
			}
		}

		tokio::runtime::Handle::current()
			.block_on(deposit_aggregator.aggregate_bytes(&leaf_proofs))
			.map_err(|e| anyhow::anyhow!("deposit aggregation: {e}"))
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

		// ── 5. SuperAggregatorV2 Plonky2 proof ──────────────────────────────
		info!(batch_id, "running SuperAggregatorV2 Plonky2 proof");
		let (sa_root_proof, super_pi_commitment) = self
			.super_aggregator
			.prove_plonky2(
				tx_agg_proof,
				sr_proof,
				request.root,
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

/// Mirror of Solidity `TesseraRollupV2.keccakToPublicInputs`.
///
/// Splits a 32-byte Keccak-256 piCommitment into 8 big-endian uint32 words,
/// matching the gnark Groth16 verifier's public input layout.
///
/// This is the inverse of the packing done in `SuperAggregatorV2Service::prove_plonky2`:
/// `commitment[i*4..(i+1)*4] = word[i].to_be_bytes()`.
pub fn keccak_to_public_inputs(commitment: &[u8; 32]) -> [u32; 8] {
	core::array::from_fn(|i| u32::from_be_bytes(commitment[i * 4..(i + 1) * 4].try_into().unwrap()))
}

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

/// Parse the Groth16 solidity JSON (produced by `Groth16Wrapper::proof_to_solidity_json`)
/// into a [`SolidityProof`].
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
