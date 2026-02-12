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
		ChainedInsertProofTargets, NullifierChainedInsertProof,
	},
	CircuitDataNative, ConfigNative, D, F,
};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::types::{ProveOutcome, ProveRequest, SolidityProof};

/// Encapsulates the full proof pipeline: plonky2 -> BN128 wrap -> Groth16.
pub struct ProverService {
	circuit_data: CircuitDataNative,
	targets: ChainedInsertProofTargets,
	bn128_wrapper: BN128Wrapper,
}

impl ProverService {
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

		Groth16Wrapper::init(plonky2_data_path, groth16_artifacts_path)?;
		Groth16Wrapper::check_init();

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let sha256_com = Sha256Commitment::new(&mut builder, 8);
		let targets =
			ChainedInsertProofTargets::new::<F, D>(&mut builder, 32, batch_size, Some(&sha256_com));
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
	pub fn prove(&self, batch_proof: &NullifierChainedInsertProof<Hash>) -> Result<SolidityProof> {
		let mut pw = PartialWitness::new();
		self.targets.set::<Hash, F, 32>(&mut pw, batch_proof)?;

		let plonky2_proof = self.circuit_data.prove(pw)?;
		self.circuit_data.verify(plonky2_proof.clone())?;

		let bn128_proof = self.bn128_wrapper.wrap_proof_to_bn128(plonky2_proof)?;
		let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(bn128_proof)?;
		Groth16Wrapper::verify(g16_proof.clone(), g16_pub_inp.clone())?;

		let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
		parse_solidity_proof_json(&solidity_json)
	}
}

/// Run the prover on a blocking thread, processing requests from a channel.
pub fn prover_thread(
	plonky2_data_path: std::path::PathBuf,
	groth16_artifacts_path: std::path::PathBuf,
	batch_size: usize,
	mut rx: mpsc::Receiver<ProveRequest>,
	tx: mpsc::Sender<ProveOutcome>,
) {
	let prover = match ProverService::init(&plonky2_data_path, &groth16_artifacts_path, batch_size)
	{
		Ok(p) => p,
		Err(e) => {
			error!("prover initialization failed: {e}");
			return;
		},
	};

	while let Some(request) = rx.blocking_recv() {
		let Some(new_root) = request.batch_proof.final_root() else {
			let _ = tx.blocking_send(ProveOutcome::Failure {
				error: "empty consume batch proof".to_string(),
			});
			continue;
		};
		info!(
			batch_size = request.batch_proof.len(),
			"proving consume batch"
		);

		match prover.prove(&request.batch_proof) {
			Ok(solidity_proof) => {
				let outcome = ProveOutcome::Success {
					new_root,
					solidity_proof,
				};
				if tx.blocking_send(outcome).is_err() {
					info!("result channel closed, shutting down prover");
					break;
				}
			},
			Err(e) => {
				error!("proof generation failed: {e}");
				let outcome = ProveOutcome::Failure {
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
