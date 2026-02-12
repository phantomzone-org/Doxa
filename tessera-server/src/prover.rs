use std::path::Path;

use anyhow::Result;
use plonky2::{
	iop::witness::PartialWitness,
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use tessera_trees::{
	groth::{BN128Wrapper, Groth16Wrapper},
	tree::{
		hasher::{Hash, Sha256Commitment},
		BatchCommitmentProof, BatchCommitmentProofTargets,
	},
	CircuitDataNative, ConfigNative, D, F,
};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::types::{ProveOutcome, ProveRequest, SolidityProof};

/// Encapsulates the full proof pipeline: plonky2 -> BN128 wrap -> Groth16.
///
/// Initialized once (expensive), then `prove()` is called per-batch.
/// Must run on a single OS thread (Go FFI is not thread-safe).
pub struct ProverService {
	circuit_data: CircuitDataNative,
	targets: BatchCommitmentProofTargets,
	bn128_wrapper: BN128Wrapper,
}

impl ProverService {
	/// Initialize the prover: build the circuit, load Groth16 keys.
	///
	/// This is expensive (can take minutes on first run for trusted setup).
	pub fn init(plonky2_data_path: &Path, groth16_artifacts_path: &Path) -> Result<Self> {
		// 1. Load BN128 wrapper from pre-generated artifacts — fails if missing.
		if !BN128Wrapper::has_full_artifacts(plonky2_data_path) {
			return Err(anyhow::anyhow!(
				"BN128 artifacts not found at {:?}. \
				 Run `cargo run --bin pending_deposit_artifacts --release` first.",
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

		// 5. Initialize Groth16 (loads R1CS + keys).
		Groth16Wrapper::init(plonky2_data_path, groth16_artifacts_path)?;
		Groth16Wrapper::check_init();

		// 6. Build the reusable prover circuit. The circuit shape is fixed (depth=32, batch=128,
		//    SHA-256 commitment).
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let sha256_com = Sha256Commitment::new(&mut builder, 8);
		let targets =
			BatchCommitmentProofTargets::new::<F, D>(&mut builder, 32, 128, Some(&sha256_com));
		targets.connect::<Hash, F, D>(&mut builder);
		let circuit_data = builder.build::<ConfigNative>();

		info!("prover initialized");

		Ok(Self {
			circuit_data,
			targets,
			bn128_wrapper,
		})
	}

	/// Generate a complete Groth16 proof for the given batch.
	///
	/// This is a blocking, CPU-intensive operation.
	pub fn prove(&self, batch_proof: &BatchCommitmentProof<Hash>) -> Result<SolidityProof> {
		// 1. Set witnesses on the pre-built circuit.
		let mut pw = PartialWitness::new();
		self.targets.set::<Hash, F, 32>(&mut pw, batch_proof)?;

		// 2. Prove plonky2 (native Goldilocks).
		let plonky2_proof = self.circuit_data.prove(pw)?;
		self.circuit_data.verify(plonky2_proof.clone())?;

		// 3. Wrap to BN128.
		let bn128_proof = self.bn128_wrapper.wrap_proof_to_bn128(plonky2_proof)?;

		// 4. Groth16 prove via Go FFI.
		let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(bn128_proof)?;

		// 5. Verify locally.
		Groth16Wrapper::verify(g16_proof.clone(), g16_pub_inp.clone())?;

		// 6. Format for Solidity.
		let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
		parse_solidity_proof_json(&solidity_json)
	}
}

/// Run the prover on a blocking thread, processing requests from a channel.
///
/// This function is meant to be called via `tokio::task::spawn_blocking`.
/// It blocks the thread, receiving `ProveRequest`s and sending back `ProveResult`s.
pub fn prover_thread(
	plonky2_data_path: std::path::PathBuf,
	groth16_artifacts_path: std::path::PathBuf,
	mut rx: mpsc::Receiver<ProveRequest>,
	tx: mpsc::Sender<ProveOutcome>,
) {
	// Initialize prover (expensive, one-time).
	let prover = match ProverService::init(&plonky2_data_path, &groth16_artifacts_path) {
		Ok(p) => p,
		Err(e) => {
			error!("prover initialization failed: {e}");
			return;
		},
	};

	// Process prove requests sequentially.
	while let Some(request) = rx.blocking_recv() {
		let start_index = request.deposit_start_index;
		info!(start_index, "proving batch");

		let new_root = request.batch_proof.root_new;

		match prover.prove(&request.batch_proof) {
			Ok(solidity_proof) => {
				let outcome = ProveOutcome::Success {
					deposit_start_index: start_index,
					new_root,
					solidity_proof,
				};
				if tx.blocking_send(outcome).is_err() {
					info!("result channel closed, shutting down prover");
					break;
				}
				info!(start_index, "proof generated");
			},
			Err(e) => {
				error!(start_index, "proof generation failed: {e}");
				let outcome = ProveOutcome::Failure {
					deposit_start_index: start_index,
					error: e.to_string(),
				};
				if tx.blocking_send(outcome).is_err() {
					info!("result channel closed, shutting down prover");
					break;
				}
			},
		}
	}

	info!("prover thread exiting");
}

/// Parse the JSON from `Groth16Wrapper::proof_to_solidity_json` into
/// typed `U256` arrays for the contract call.
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
