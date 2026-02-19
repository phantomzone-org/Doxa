use std::path::Path;

use anyhow::Result;
use plonky2::{
	iop::witness::PartialWitness,
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use tessera_trees::{
	groth::{BN128Wrapper, Groth16Wrapper},
	tree::{
		hasher::{Hash, Keccak256Commitment},
		BatchCommitmentProof, BatchCommitmentProofTargets, ChainedInsertProofTargets,
		NullifierChainedInsertProof,
	},
	CircuitDataNative, ConfigNative, D, F,
};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::types::{ProveOutcome, ProveRequest, SolidityProof};

const DUMMY_ASSOCIATED_INPUT_PROOF: &[u8] = &[0x01];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveGroth {
	Commitment,
	Nullifier,
}

/// Encapsulates the full proof pipeline: plonky2 -> BN128 wrap -> Groth16.
pub struct CommitmentProverService {
	circuit_data: CircuitDataNative,
	targets: BatchCommitmentProofTargets,
	bn128_wrapper: BN128Wrapper,
}

pub struct NullifierProverService {
	circuit_data: CircuitDataNative,
	targets: ChainedInsertProofTargets,
	bn128_wrapper: BN128Wrapper,
}

/// In-process prover runtime that can serve remote prove requests.
///
/// Groth16Wrapper is a global FFI singleton, so this runtime keeps track
/// of the currently loaded circuit and reinitializes it only when the
/// incoming job type changes.
pub struct ProverRuntime {
	commitment_prover: CommitmentProverService,
	nullifier_prover: NullifierProverService,
	commitment_plonky2_data_path: std::path::PathBuf,
	commitment_groth16_artifacts_path: std::path::PathBuf,
	nullifier_plonky2_data_path: std::path::PathBuf,
	nullifier_groth16_artifacts_path: std::path::PathBuf,
	active: Option<ActiveGroth>,
}

impl CommitmentProverService {
	/// Initialize the prover: build the circuit, load Groth16 keys.
	pub fn init(
		plonky2_data_path: &Path,
		groth16_artifacts_path: &Path,
		batch_size: usize,
	) -> Result<Self> {
		if !BN128Wrapper::has_full_artifacts(plonky2_data_path) {
			return Err(anyhow::anyhow!(
				"BN128 artifacts not found at {:?}. \
				 Run `cargo run --bin used_deposit_artifacts --release` first.",
				plonky2_data_path
			));
		}
		info!("loading BN128 wrapper from artifacts");
		let bn128_wrapper = BN128Wrapper::from_artifacts(plonky2_data_path)?;

		if !groth16_artifacts_path.is_dir() {
			return Err(anyhow::anyhow!(
				"groth16 artifacts path not found: {:?}. Generate artifacts first.",
				groth16_artifacts_path
			));
		}

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let keccak_com = Keccak256Commitment::<ConfigNative, D>::new(&mut builder);
		let targets = BatchCommitmentProofTargets::new::<F, D>(
			&mut builder,
			32,
			batch_size,
			Some(&keccak_com),
		);
		targets.connect::<Hash, F, D>(&mut builder);
		let circuit_data = builder.build::<ConfigNative>();

		info!(batch_size, "prover initialized");

		Ok(Self {
			circuit_data,
			targets,
			bn128_wrapper,
		})
	}

	/// Generate a complete Groth16 proof for the given consume batch.
	pub fn prove(&self, batch_proof: &BatchCommitmentProof<Hash>) -> Result<SolidityProof> {
		let mut pw = PartialWitness::new();
		self.targets.set::<Hash, F, 32>(&mut pw, batch_proof)?;

		let plonky2_proof = self.circuit_data.prove(pw)?;
		self.circuit_data.verify(plonky2_proof.clone())?;

		let bn128_proof = self.bn128_wrapper.wrap_proof_to_bn128(plonky2_proof)?;
		let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(bn128_proof)?;
		// Call proof_to_solidity_json (takes &[u8]) before verify (takes Vec<u8>) to
		// avoid cloning g16_proof and g16_pub_inp.
		let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
		Groth16Wrapper::verify(g16_proof, g16_pub_inp)?;
		parse_solidity_proof_json(&solidity_json)
	}
}

impl NullifierProverService {
	pub fn init(
		plonky2_data_path: &Path,
		groth16_artifacts_path: &Path,
		batch_size: usize,
	) -> Result<Self> {
		if !BN128Wrapper::has_full_artifacts(plonky2_data_path) {
			return Err(anyhow::anyhow!(
				"BN128 artifacts not found at {:?}. \
				 Run `cargo run --bin nullifier_tree_artifacts --release` first.",
				plonky2_data_path
			));
		}
		info!("loading BN128 wrapper (nullifier) from artifacts");
		let bn128_wrapper = BN128Wrapper::from_artifacts(plonky2_data_path)?;

		if !groth16_artifacts_path.is_dir() {
			return Err(anyhow::anyhow!(
				"groth16 artifacts path not found: {:?}. Generate artifacts first.",
				groth16_artifacts_path
			));
		}

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let keccak_com = Keccak256Commitment::<ConfigNative, D>::new(&mut builder);
		let targets =
			ChainedInsertProofTargets::new::<F, D>(&mut builder, 32, batch_size, Some(&keccak_com));
		targets.connect::<Hash, F, D>(&mut builder);
		let circuit_data = builder.build::<ConfigNative>();

		info!(batch_size, "nullifier prover initialized");

		Ok(Self {
			circuit_data,
			targets,
			bn128_wrapper,
		})
	}

	pub fn prove(&self, batch_proof: &NullifierChainedInsertProof<Hash>) -> Result<SolidityProof> {
		let mut pw = PartialWitness::new();
		self.targets.set::<Hash, F, 32>(&mut pw, batch_proof)?;

		let plonky2_proof = self.circuit_data.prove(pw)?;
		self.circuit_data.verify(plonky2_proof.clone())?;

		let bn128_proof = self.bn128_wrapper.wrap_proof_to_bn128(plonky2_proof)?;
		let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(bn128_proof)?;
		// Call proof_to_solidity_json (takes &[u8]) before verify (takes Vec<u8>) to
		// avoid cloning g16_proof and g16_pub_inp.
		let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
		Groth16Wrapper::verify(g16_proof, g16_pub_inp)?;
		parse_solidity_proof_json(&solidity_json)
	}
}

impl ProverRuntime {
	fn dummy_verify_and_aggregate_associated_input_proofs(
		associated_input_proofs: &[Vec<u8>],
		expected_count: usize,
	) -> Result<SolidityProof> {
		anyhow::ensure!(
			associated_input_proofs.len() == expected_count,
			"associated input proof count mismatch: got {}, expected {}",
			associated_input_proofs.len(),
			expected_count
		);
		for (i, proof) in associated_input_proofs.iter().enumerate() {
			anyhow::ensure!(
				proof.as_slice() == DUMMY_ASSOCIATED_INPUT_PROOF,
				"associated input proof {i} failed dummy verification (expected 0x01)"
			);
		}
		// Dummy aggregation output for Phase A. Contract-side aggregated-input
		// verifier is also dummy and accepts this placeholder proof.
		Ok(SolidityProof {
			proof: [alloy::primitives::U256::ZERO; 8],
			commitments: [alloy::primitives::U256::ZERO; 2],
			commitment_pok: [alloy::primitives::U256::ZERO; 2],
		})
	}

	pub fn init(
		commitment_plonky2_data_path: std::path::PathBuf,
		commitment_groth16_artifacts_path: std::path::PathBuf,
		nullifier_plonky2_data_path: std::path::PathBuf,
		nullifier_groth16_artifacts_path: std::path::PathBuf,
		batch_size: usize,
	) -> Result<Self> {
		let commitment_prover = CommitmentProverService::init(
			&commitment_plonky2_data_path,
			&commitment_groth16_artifacts_path,
			batch_size,
		)?;
		let nullifier_prover = NullifierProverService::init(
			&nullifier_plonky2_data_path,
			&nullifier_groth16_artifacts_path,
			batch_size,
		)?;
		Ok(Self {
			commitment_prover,
			nullifier_prover,
			commitment_plonky2_data_path,
			commitment_groth16_artifacts_path,
			nullifier_plonky2_data_path,
			nullifier_groth16_artifacts_path,
			active: None,
		})
	}

	pub fn prove_request(&mut self, request: ProveRequest) -> ProveOutcome {
		let (need_active, new_root, batch_size, associated_input_proofs) = match &request {
			ProveRequest::Commitment {
				batch_proof,
				associated_input_proofs,
			} => (
				ActiveGroth::Commitment,
				batch_proof.root_new,
				batch_proof.leaves.len(),
				associated_input_proofs,
			),
			ProveRequest::Nullifier {
				batch_proof,
				associated_input_proofs,
			} => {
				let Some(last) = batch_proof.proofs.last() else {
					return ProveOutcome::Failure {
						error: "nullifier proof request contains no insertions".to_string(),
					};
				};
				(
					ActiveGroth::Nullifier,
					last.new_root,
					batch_proof.len(),
					associated_input_proofs,
				)
			},
		};

		if self.active != Some(need_active) {
			let init_res = match need_active {
				ActiveGroth::Commitment => Groth16Wrapper::init(
					&self.commitment_plonky2_data_path,
					&self.commitment_groth16_artifacts_path,
				),
				ActiveGroth::Nullifier => Groth16Wrapper::init(
					&self.nullifier_plonky2_data_path,
					&self.nullifier_groth16_artifacts_path,
				),
			};
			if let Err(e) = init_res {
				error!("groth16 init failed: {e}");
				return ProveOutcome::Failure {
					error: e.to_string(),
				};
			}
			Groth16Wrapper::check_init();
			self.active = Some(need_active);
		}

		let proof_res = match &request {
			ProveRequest::Commitment {
				batch_proof, ..
			} => {
				info!(batch_size, "proving commitment batch");
				self.commitment_prover.prove(batch_proof)
			},
			ProveRequest::Nullifier {
				batch_proof, ..
			} => {
				info!(batch_size, "proving nullifier batch");
				self.nullifier_prover.prove(batch_proof)
			},
		};
		let aggregated_input_proof_res = Self::dummy_verify_and_aggregate_associated_input_proofs(
			associated_input_proofs,
			batch_size,
		);

		match (proof_res, aggregated_input_proof_res) {
			(Ok(solidity_proof), Ok(aggregated_input_solidity_proof)) => ProveOutcome::Success {
				new_root,
				solidity_proof: Box::new(solidity_proof),
				aggregated_input_solidity_proof: Box::new(aggregated_input_solidity_proof),
			},
			(_, Err(e)) => {
				error!("associated input proof aggregation failed: {e}");
				ProveOutcome::Failure {
					error: e.to_string(),
				}
			},
			(Err(e), _) => {
				error!("proof generation failed: {e}");
				ProveOutcome::Failure {
					error: e.to_string(),
				}
			},
		}
	}
}

/// Run the prover on a blocking thread, processing requests from a channel.
pub fn prover_thread(
	plonky2_data_path: std::path::PathBuf,
	groth16_artifacts_path: std::path::PathBuf,
	nullifier_plonky2_data_path: std::path::PathBuf,
	nullifier_groth16_artifacts_path: std::path::PathBuf,
	batch_size: usize,
	mut rx: mpsc::Receiver<ProveRequest>,
	tx: mpsc::Sender<ProveOutcome>,
) {
	let commitment_prover = match CommitmentProverService::init(
		&plonky2_data_path,
		&groth16_artifacts_path,
		batch_size,
	) {
		Ok(p) => p,
		Err(e) => {
			error!("commitment prover initialization failed: {e}");
			return;
		},
	};
	let nullifier_prover = match NullifierProverService::init(
		&nullifier_plonky2_data_path,
		&nullifier_groth16_artifacts_path,
		batch_size,
	) {
		Ok(p) => p,
		Err(e) => {
			error!("nullifier prover initialization failed: {e}");
			return;
		},
	};

	let mut runtime = ProverRuntime {
		commitment_prover,
		nullifier_prover,
		commitment_plonky2_data_path: plonky2_data_path,
		commitment_groth16_artifacts_path: groth16_artifacts_path,
		nullifier_plonky2_data_path,
		nullifier_groth16_artifacts_path,
		active: None,
	};

	while let Some(request) = rx.blocking_recv() {
		let outcome = runtime.prove_request(request);
		if tx.blocking_send(outcome).is_err() {
			info!("result channel closed, shutting down prover");
			break;
		}
	}

	info!("prover thread exiting");
}

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
