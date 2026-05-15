use std::{fs, path::Path};

use anyhow::{anyhow, Result};
use plonky2::{
	plonk::circuit_data::{CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
	util::serialization::{DefaultGateSerializer, GateSerializer},
};
use serde::{Deserialize, Serialize};
use tessera_utils::{groth::TesseraGeneratorSerializer, ConfigNative, D, F};

// ---------------------------------------------------------------------------
// Artifact persistence — concrete types only
// ---------------------------------------------------------------------------
//
// `TesseraGeneratorSerializer` implements `WitnessGeneratorSerializer` only for
// `(GoldilocksField, 2)`, so these methods must live on a monomorphised impl
// block rather than the generic one above.
use crate::aggregator_service::generic_aggregator::{
	level_circuit_path, setup_level_builder, GenericAggregator, GenericAggregatorConfig,
	LevelCircuit, LEAF_COMMON_PATH, LEAF_VERIFIER_PATH, MANIFEST_PATH, MANIFEST_VERSION,
};

// Internal manifest used for artifact persistence.
#[derive(Debug, Serialize, Deserialize)]
struct AggregatorManifest {
	version: u32,
	arity: usize,
	depth: usize,
	leaf_pi_len: usize,
	levels: usize,
}

impl GenericAggregator<tessera_utils::F, tessera_utils::ConfigNative, 2> {
	/// Persist all circuit artifacts to `path`.
	///
	/// Creates the directory if it does not exist.  Overwrites any existing
	/// artifacts.  Delete `path` before calling if you need a clean rebuild.
	///
	/// `leaf_gate_ser` is the gate serializer used for `leaf_common.bin`.
	/// Pass `&DefaultGateSerializer` when the leaf circuit uses only standard
	/// plonky2 gates, or a custom serializer (e.g. `TesseraGateSerializer`)
	/// when the leaf circuit contains custom gates.

	pub fn store_artifacts(
		&self,
		path: &Path,
		leaf_gate_ser: &dyn GateSerializer<F, 2>,
	) -> Result<()> {
		fs::create_dir_all(path)?;

		let manifest = AggregatorManifest {
			version: MANIFEST_VERSION,
			arity: self.config.arity,
			depth: self.config.depth,
			leaf_pi_len: self.leaf_common.num_public_inputs,
			levels: self.config.depth,
		};
		fs::write(
			path.join(MANIFEST_PATH),
			serde_json::to_string_pretty(&manifest)?,
		)?;

		let gate_ser = DefaultGateSerializer;

		let common_bytes = self
			.leaf_common
			.to_bytes(leaf_gate_ser)
			.map_err(|_| anyhow!("serialize leaf_common failed"))?;
		fs::write(path.join(LEAF_COMMON_PATH), common_bytes)?;

		let verifier_bytes = self
			.leaf_verifier
			.to_bytes()
			.map_err(|_| anyhow!("serialize leaf_verifier failed"))?;
		fs::write(path.join(LEAF_VERIFIER_PATH), verifier_bytes)?;
		for (i, level) in self.levels.iter().enumerate() {
			let bytes = level
				.circuit_data
				.to_bytes(&gate_ser, &TesseraGeneratorSerializer)
				.map_err(|_| {
					anyhow!(
						"serialize level {i} circuit failed (plonky2 IoError). \
                         If a new custom generator was added, register it in \
                         tessera-trees/src/groth/serializer.rs."
					)
				})?;
			fs::write(path.join(level_circuit_path(i)), bytes)?;
		}

		Ok(())
	}

	/// Reconstruct a [`GenericAggregator`] from pre-generated artifacts without
	/// recompiling any circuits.
	///
	/// Follows the required bottom-up loading order: level-N's circuit was built
	/// against level-(N-1)'s `CommonCircuitData`, so targets are rebuilt in the
	/// same order to obtain correct wire indices.
	///
	/// `leaf_gate_ser` is the gate serializer used for `leaf_common.bin`.
	/// Must match the serializer used in [`store_artifacts`].

	pub fn from_artifacts(path: &Path, leaf_gate_ser: &dyn GateSerializer<F, 2>) -> Result<Self> {
		let manifest_path = path.join(MANIFEST_PATH);
		let manifest: AggregatorManifest = serde_json::from_str(
			&fs::read_to_string(&manifest_path)
				.map_err(|e| anyhow!("failed to read '{}': {e}", manifest_path.display()))?,
		)?;

		if manifest.version != MANIFEST_VERSION {
			anyhow::bail!(
				"manifest version mismatch in '{}': expected {}, got {}",
				path.display(),
				MANIFEST_VERSION,
				manifest.version
			);
		}

		let config = GenericAggregatorConfig {
			arity: manifest.arity,
			depth: manifest.depth,
		};
		config.validate()?;

		let gate_ser = DefaultGateSerializer;

		let leaf_common_path = path.join(LEAF_COMMON_PATH);
		let leaf_common_bytes = fs::read(&leaf_common_path)
			.map_err(|e| anyhow!("failed to read '{}': {e}", leaf_common_path.display()))?;
		let leaf_common: CommonCircuitData<F, D> =
			CommonCircuitData::from_bytes(&leaf_common_bytes, leaf_gate_ser).map_err(|_| {
				anyhow!(
					"deserialize leaf_common from '{}' failed",
					leaf_common_path.display()
				)
			})?;

		let leaf_verifier_path = path.join(LEAF_VERIFIER_PATH);
		let leaf_verifier_bytes = fs::read(&leaf_verifier_path)
			.map_err(|e| anyhow!("failed to read '{}': {e}", leaf_verifier_path.display()))?;
		let leaf_verifier: VerifierOnlyCircuitData<ConfigNative, 2> =
			VerifierOnlyCircuitData::from_bytes(&leaf_verifier_bytes).map_err(|_| {
				anyhow!(
					"deserialize leaf_verifier from '{}' failed",
					leaf_verifier_path.display()
				)
			})?;

		// Bottom-up loading.  Level 0 uses leaf_common/leaf_verifier; each
		// subsequent level uses the previous level's circuit data.
		let mut inner_common = leaf_common.clone();
		let mut inner_verifier = leaf_verifier.clone();
		let mut levels: Vec<LevelCircuit<F, ConfigNative, 2>> = Vec::with_capacity(config.depth);

		for i in 0..config.depth {
			// Replay the exact same deterministic builder operations used in `new`
			// to recover the target wire indices.  No `build()` or `prove()` call
			// is needed; the builder is discarded after extracting targets.
			let (_, proof_targets, verifier_target) = setup_level_builder::<F, ConfigNative, 2>(
				&inner_common,
				&inner_verifier,
				config.arity,
			);

			let level_path = path.join(level_circuit_path(i));
			let bytes = fs::read(&level_path)
				.map_err(|e| anyhow!("failed to read '{}': {e}", level_path.display()))?;
			let circuit_data = CircuitData::<F, ConfigNative, D>::from_bytes(
				&bytes,
				&gate_ser,
				&TesseraGeneratorSerializer,
			)
			.map_err(|_| {
				anyhow!(
					"deserialize level {i} circuit from '{}' failed (plonky2 IoError). \
                             Possible causes: (1) artifacts from a different plonky2 revision; \
                             (2) file truncated or corrupt; (3) a generator present at \
                             serialization time is missing from TesseraGeneratorSerializer. \
                             Delete the artifacts directory and regenerate.",
					level_path.display()
				)
			})?;

			// Advance inner circuit data for the next level.
			if i + 1 < config.depth {
				inner_common = circuit_data.common.clone();
				inner_verifier = circuit_data.verifier_only.clone();
			}

			levels.push(LevelCircuit {
				circuit_data,
				proof_targets,
				verifier_target,
			});
		}

		Ok(Self {
			config,
			leaf_common,
			leaf_verifier,
			levels,
		})
	}

	/// Returns `Ok(true)` if the full artifact set required by
	/// [`from_artifacts`] is present under `path`.
	pub fn has_full_artifacts(path: &Path) -> Result<bool> {
		if !path.join(MANIFEST_PATH).is_file()
			|| !path.join(LEAF_COMMON_PATH).is_file()
			|| !path.join(LEAF_VERIFIER_PATH).is_file()
		{
			return Ok(false);
		}

		// Parse the manifest to discover how many level files to expect.
		let manifest: AggregatorManifest = match fs::read_to_string(path.join(MANIFEST_PATH)) {
			Ok(s) => match serde_json::from_str(&s) {
				Ok(m) => m,
				Err(_) => return Ok(false),
			},
			Err(_) => return Ok(false),
		};

		for i in 0..manifest.levels {
			if !path.join(level_circuit_path(i)).is_file() {
				return Ok(false);
			}
		}

		Ok(true)
	}
}
