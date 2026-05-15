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
	targets::{PrivTxSuperCircuitData, PrivTxSuperTargets},
};

// ---------------------------------------------------------------------------
// Artifact path constants
// ---------------------------------------------------------------------------

pub(super) const CIRCUIT_DATA_PATH: &str = "circuit_data.bin";
pub(super) const TX_COMMON_PATH: &str = "tx_common.bin";
pub(super) const TX_VERIFIER_PATH: &str = "tx_verifier.bin";
pub(super) const SR_COMMON_PATH: &str = "sr_common.bin";
pub(super) const SR_VERIFIER_PATH: &str = "sr_verifier.bin";

const ARTIFACT_FILES: &[&str] = &[
	CIRCUIT_DATA_PATH,
	TX_COMMON_PATH,
	TX_VERIFIER_PATH,
	SR_COMMON_PATH,
	SR_VERIFIER_PATH,
];

// ---------------------------------------------------------------------------
// PrivTxSuperCircuit
// ---------------------------------------------------------------------------

/// Recursion circuit that:
/// 1. Verifies a TX aggregation proof and a SubtreeRoot proof.
/// 2. Cross-checks SR leaves against TX output commitments.
/// 3. Asserts uniform `act_root` / `mainpool_config_root` across all TX slots.
/// 4. Emits `super_pi_commitment = Keccak256(preimage)` as 8 u32 public inputs.
pub struct PrivTxSuperCircuit {
	pub circuit_data: CircuitDataNative,
	pub(super) targets: PrivTxSuperTargets,
	pub(super) inner: PrivTxSuperCircuitData,
}

impl PrivTxSuperCircuit {
	/// Build the circuit from the two inner [`CircuitData`] objects.
	pub fn build(inner: PrivTxSuperCircuitData) -> Result<Self> {
		let (builder, targets) = setup_super_builder(&inner);
		let circuit_data = builder.build::<ConfigNative>();
		Ok(Self {
			circuit_data,
			targets,
			inner,
		})
	}

	/// Prove: verify both inner proofs and emit the 8-word `super_pi_commitment`.
	pub fn prove(&self, tx: ProofNative, sr: ProofNative) -> Result<ProofNative> {
		let mut pw = PartialWitness::new();
		pw.set_proof_with_pis_target(&self.targets.tx_proof, &tx)
			.map_err(|e| anyhow!("set tx_proof: {e}"))?;
		pw.set_proof_with_pis_target(&self.targets.sr_proof, &sr)
			.map_err(|e| anyhow!("set sr_proof: {e}"))?;
		self.circuit_data
			.prove(pw)
			.map_err(|e| anyhow!("PrivTxSuperCircuit::prove: {e}"))
	}

	/// Persist all artifacts to `path/`.
	pub fn store_artifacts(&self, path: &Path) -> Result<()> {
		fs::create_dir_all(path)?;
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let cd_bytes = self
			.circuit_data
			.to_bytes(&gate_ser, &gen_ser)
			.map_err(|_| anyhow!("serialize PrivTxSuperCircuit circuit_data failed"))?;
		fs::write(path.join(CIRCUIT_DATA_PATH), cd_bytes)?;

		write_common(path.join(TX_COMMON_PATH), &self.inner.tx_common, &gate_ser)?;
		write_verifier(path.join(TX_VERIFIER_PATH), &self.inner.tx_verifier)?;
		write_common(path.join(SR_COMMON_PATH), &self.inner.sr_common, &gate_ser)?;
		write_verifier(path.join(SR_VERIFIER_PATH), &self.inner.sr_verifier)?;
		Ok(())
	}

	/// Reconstruct from pre-generated artifacts without recompiling.
	pub fn from_artifacts(path: &Path) -> Result<Self> {
		let gate_ser = DefaultGateSerializer;
		let gen_ser = TesseraGeneratorSerializer;

		let tx_common = read_common(path.join(TX_COMMON_PATH), &gate_ser, "tx_common")?;
		let tx_verifier = read_verifier(path.join(TX_VERIFIER_PATH), "tx_verifier")?;
		let sr_common = read_common(path.join(SR_COMMON_PATH), &gate_ser, "sr_common")?;
		let sr_verifier = read_verifier(path.join(SR_VERIFIER_PATH), "sr_verifier")?;

		let inner = PrivTxSuperCircuitData {
			tx_common,
			tx_verifier,
			sr_common,
			sr_verifier,
		};
		let (_, targets) = setup_super_builder(&inner);

		let cd_bytes = fs::read(path.join(CIRCUIT_DATA_PATH))
			.map_err(|e| anyhow!("failed to read circuit_data.bin: {e}"))?;
		let circuit_data =
			CircuitDataNative::from_bytes(&cd_bytes, &gate_ser, &gen_ser).map_err(|_| {
				anyhow!(
					"deserialize PrivTxSuperCircuit circuit_data failed. \
					 Delete the artifacts directory and rebuild."
				)
			})?;

		Ok(Self {
			circuit_data,
			targets,
			inner,
		})
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
