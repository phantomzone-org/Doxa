use std::path::Path;

use anyhow::Result;
use tessera_utils::{
	groth::{BN128Wrapper, Groth16Wrapper},
	ProofNative,
};
use tracing::info;

use crate::{aggregator_service::utils::parse_solidity_proof_json, types::SolidityProof};

/// Wraps [`SuperAggregator`] + BN128 + Groth16 for end-to-end proving.
pub struct BN128WrapperService {
	bn128_wrapper: BN128Wrapper,
}

impl BN128WrapperService {
	/// Load from pre-built artifacts at `path`.
	///
	/// Also loads the BN128 wrapper and initialises the global Groth16 FFI singleton.
	pub fn from_artifacts(path: &Path) -> Result<Self> {
		let plonky2_path = path.join("plonky2-proof");
		let groth16_artifacts_path = path.join("groth-artifacts");

		if !BN128Wrapper::has_full_artifacts(&plonky2_path) {
			return Err(anyhow::anyhow!(
				"BN128 wrapper artifacts not found at {:?}",
				plonky2_path
			));
		}
		info!("loading BN128 wrapper from artifacts");
		let bn128_wrapper = BN128Wrapper::from_artifacts(&plonky2_path)?;

		info!("initialising Groth16 singleton for SuperAggregator");
		Groth16Wrapper::init(&plonky2_path, &groth16_artifacts_path)?;
		Groth16Wrapper::check_init();

		Ok(Self {
			bn128_wrapper,
		})
	}

	/// Stage 2: BN128 wrap + Groth16 prove.
	pub fn wrap_groth16(&self, root_proof: ProofNative) -> Result<SolidityProof> {
		let bn128_proof = self
			.bn128_wrapper
			.wrap_proof_to_bn128(root_proof)
			.map_err(|e| anyhow::anyhow!("Final Plonky2 Proof BN128 wrap: {e}"))?;

		let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(bn128_proof)
			.map_err(|e| anyhow::anyhow!("Final Plonky2 Proof Groth16: {e}"))?;
		let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)
			.map_err(|e| anyhow::anyhow!("Final Plonky2 Proof solidity JSON: {e}"))?;
		Groth16Wrapper::verify(g16_proof, g16_pub_inp)
			.map_err(|e| anyhow::anyhow!("Final Plonky2 Proof Groth16 verify: {e}"))?;
		parse_solidity_proof_json(&solidity_json)
	}
}
