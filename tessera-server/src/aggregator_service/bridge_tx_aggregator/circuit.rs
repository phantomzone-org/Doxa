use std::{fs, path::Path};

use anyhow::{anyhow, Result};
use plonky2::{
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
	util::serialization::DefaultGateSerializer,
};
use tessera_utils::{groth::TesseraGeneratorSerializer, CircuitDataNative, ConfigNative, ProofNative, D, F};

use super::{
	circuit_builder::setup_super_builder,
	targets::{BridgeTxSuperCircuitData, BridgeTxSuperTargets},
};

// ---------------------------------------------------------------------------
// Artifact path constants
// ---------------------------------------------------------------------------

pub(super) const CIRCUIT_DATA_PATH: &str = "circuit_data.bin";
pub(super) const PAIR_COMMON_PATH: &str = "pair_common.bin";
pub(super) const PAIR_VERIFIER_PATH: &str = "pair_verifier.bin";
pub(super) const SR_COMMON_PATH: &str = "sr_common.bin";
pub(super) const SR_VERIFIER_PATH: &str = "sr_verifier.bin";

const ARTIFACT_FILES: &[&str] = &[
	CIRCUIT_DATA_PATH,
	PAIR_COMMON_PATH,
	PAIR_VERIFIER_PATH,
	SR_COMMON_PATH,
	SR_VERIFIER_PATH,
];

// ---------------------------------------------------------------------------
// BridgeTxSuperCircuit
// ---------------------------------------------------------------------------

/// Recursion circuit that:
/// 1. Verifies the pair-aggregation proof (root of 256 W+D pair proofs).
/// 2. Verifies the SubtreeRoot (SR) proof over 512 output commitments.
/// 3. Cross-checks SR leaves against TX output commitments.
/// 4. Asserts uniform `act_root` / `mainpool_config_root` across all pair slots.
/// 5. Emits `super_pi_commitment = Keccak256(preimage)` as 8 u32 public inputs.
pub struct BridgeTxSuperCircuit {
	pub circuit_data: CircuitDataNative,
	pub(super) targets: BridgeTxSuperTargets,
	pub(super) inner: BridgeTxSuperCircuitData,
}

impl BridgeTxSuperCircuit {
	/// Build the circuit from the pair-agg and SR inner [`CircuitData`] objects.
	pub fn build(inner: BridgeTxSuperCircuitData) -> Result<Self> {
		let (builder, targets) = setup_super_builder(&inner);
		let circuit_data = builder.build::<ConfigNative>();
		Ok(Self { circuit_data, targets, inner })
	}

	/// Prove: verify pair-aggregation proof + SR proof, emit the 8-word
	/// `super_pi_commitment`.
	pub fn prove(&self, pair_agg: ProofNative, sr: ProofNative) -> Result<ProofNative> {
		let mut pw = PartialWitness::new();
		pw.set_proof_with_pis_target(&self.targets.pair_proof, &pair_agg)
			.map_err(|e| anyhow!("set pair_proof: {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.poseidon_root_proof, &sr)
			.map_err(|e| anyhow!("set sr_proof: {e}"))?;
		self.circuit_data
			.prove(pw)
			.map_err(|e| anyhow!("BridgeTxSuperCircuit::prove: {e}"))
	}

	/// Persist all artifacts to `path/`.
	pub fn store_artifacts(&self, path: &Path) -> Result<()> {
		fs::create_dir_all(path)?;
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let cd_bytes = self
			.circuit_data
			.to_bytes(&gate_ser, &gen_ser)
			.map_err(|_| anyhow!("serialize BridgeTxSuperCircuit circuit_data failed"))?;
		fs::write(path.join(CIRCUIT_DATA_PATH), cd_bytes)?;

		write_common(path.join(PAIR_COMMON_PATH), &self.inner.pair_common, &gate_ser)?;
		write_verifier(path.join(PAIR_VERIFIER_PATH), &self.inner.pair_verifier)?;
		write_common(path.join(SR_COMMON_PATH), &self.inner.poseidon_root_common, &gate_ser)?;
		write_verifier(path.join(SR_VERIFIER_PATH), &self.inner.poseidon_root_verifier)?;
		Ok(())
	}

	/// Reconstruct from pre-generated artifacts without recompiling.
	///
	/// `w_unique_size` and `d_unique_size` are derived by the caller from the
	/// pair-leaf circuit's inner W/D circuit PI counts minus 8 common fields each.
	pub fn from_artifacts(path: &Path, w_unique_size: usize, d_unique_size: usize) -> Result<Self> {
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let pair_common = read_common(path.join(PAIR_COMMON_PATH), &gate_ser, "pair_common")?;
		let pair_verifier = read_verifier(path.join(PAIR_VERIFIER_PATH), "pair_verifier")?;
		let sr_common = read_common(path.join(SR_COMMON_PATH), &gate_ser, "sr_common")?;
		let sr_verifier = read_verifier(path.join(SR_VERIFIER_PATH), "sr_verifier")?;

		let inner = BridgeTxSuperCircuitData {
			pair_common,
			pair_verifier,
			poseidon_root_common: sr_common,
			poseidon_root_verifier: sr_verifier,
			w_unique_size,
			d_unique_size,
		};
		let (_, targets) = setup_super_builder(&inner);

		let cd_bytes = fs::read(path.join(CIRCUIT_DATA_PATH))
			.map_err(|e| anyhow!("failed to read circuit_data.bin: {e}"))?;
		let circuit_data =
			CircuitDataNative::from_bytes(&cd_bytes, &gate_ser, &gen_ser).map_err(|_| {
				anyhow!(
					"deserialize BridgeTxSuperCircuit circuit_data failed. \
					 Delete the artifacts directory and rebuild."
				)
			})?;

		Ok(Self { circuit_data, targets, inner })
	}

	/// Returns `true` if all artifact files are present under `path`.
	pub fn has_artifacts(path: &Path) -> bool {
		ARTIFACT_FILES.iter().all(|f| path.join(f).is_file())
	}
}

// ---------------------------------------------------------------------------
// Artifact I/O helpers
// ---------------------------------------------------------------------------

fn write_common(
	path: impl AsRef<Path>,
	data: &CommonCircuitData<F, D>,
	gate_ser: &DefaultGateSerializer,
) -> Result<()> {
	let bytes = data.to_bytes(gate_ser).map_err(|_| {
		anyhow!(
			"serialize CommonCircuitData to '{}' failed",
			path.as_ref().display()
		)
	})?;
	fs::write(path, bytes)?;
	Ok(())
}

fn write_verifier(
	path: impl AsRef<Path>,
	data: &VerifierOnlyCircuitData<ConfigNative, D>,
) -> Result<()> {
	let bytes = data.to_bytes().map_err(|_| {
		anyhow!(
			"serialize VerifierOnlyCircuitData to '{}' failed",
			path.as_ref().display()
		)
	})?;
	fs::write(path, bytes)?;
	Ok(())
}

fn read_common(
	path: impl AsRef<Path>,
	gate_ser: &DefaultGateSerializer,
	label: &str,
) -> Result<CommonCircuitData<F, D>> {
	let bytes = fs::read(&path).map_err(|e| anyhow!("failed to read {label}: {e}"))?;
	CommonCircuitData::from_bytes(&bytes, gate_ser)
		.map_err(|_| anyhow!("deserialize {label} failed"))
}

fn read_verifier(
	path: impl AsRef<Path>,
	label: &str,
) -> Result<VerifierOnlyCircuitData<ConfigNative, D>> {
	let bytes = fs::read(&path).map_err(|e| anyhow!("failed to read {label}: {e}"))?;
	VerifierOnlyCircuitData::from_bytes(&bytes)
		.map_err(|_| anyhow!("deserialize {label} failed"))
}
