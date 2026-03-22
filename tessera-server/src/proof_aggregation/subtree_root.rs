//! `SubtreeRootCircuit` — prove `root = PoseidonMerkle(leaves)` for N leaves.
//!
//! # Circuit design
//!
//! The circuit takes N leaves (4 Goldilocks elements each) as public inputs and
//! proves that their Poseidon Merkle root equals the public-input `root`.
//!
//! **Public-input layout** (Goldilocks field elements):
//! ```text
//! [root[4] | leaf0[4] | leaf1[4] | ... | leaf_{N-1}[4]]
//! ```
//! Total PI count: `(1 + N) * 4`.
//!
//! # Hash convention
//!
//! Inner nodes are always `Poseidon(left || right)` — the direction bit is
//! fixed to `false`.  This matches `HashOutput::hash_2_to_1(left, right, false)`.
//!
//! # Intended use
//!
//! In the TesseraRollupV2 design, N = 128 (depth 7). The `batch_poseidon_root`
//! is computed in-circuit from the 128 note commitments that are also embedded
//! in the TX aggregation proof, allowing `SuperAggregatorV2` to cross-check
//! them positionally.

use std::{fs, path::Path};

use anyhow::{anyhow, Result};
use plonky2::{
	iop::witness::PartialWitness,
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
	util::serialization::DefaultGateSerializer,
};
use tessera_utils::{
	groth::TesseraGeneratorSerializer,
	hasher::{HashOutput, MerkleHash, MerkleHashCircuit, MerkleHashTarget},
	CircuitDataNative, ConfigNative, ProofNative, D, F,
};

// ---------------------------------------------------------------------------
// Artifact path
// ---------------------------------------------------------------------------

const CIRCUIT_DATA_PATH: &str = "circuit_data.bin";

// ---------------------------------------------------------------------------
// Internal targets
// ---------------------------------------------------------------------------

struct SubtreeRootTargets {
	root: MerkleHashTarget<4>,
	leaves: Vec<MerkleHashTarget<4>>,
}

// ---------------------------------------------------------------------------
// SubtreeRootCircuit
// ---------------------------------------------------------------------------

/// Proves `root = PoseidonMerkle(leaves[0..N])`.
///
/// Public inputs layout:
/// ```text
/// [root[4] | leaf0[4] | leaf1[4] | ... | leaf_{N-1}[4]]
/// ```
///
/// # Artifact lifecycle
///
/// ```ignore
/// let circuit = SubtreeRootCircuit::build(128)?;
/// circuit.store_artifacts(Path::new("artifacts/subtree-root"))?;
///
/// let circuit = SubtreeRootCircuit::from_artifacts(Path::new("artifacts/subtree-root"), 128)?;
/// let proof = circuit.prove(&leaves)?;
/// ```
pub struct SubtreeRootCircuit {
	/// The compiled circuit data (needed by `BN128Wrapper`).
	pub circuit_data: CircuitDataNative,
	targets: SubtreeRootTargets,
}

impl SubtreeRootCircuit {
	/// Build the circuit for `batch_size` leaves.
	///
	/// `batch_size` must be a power of two (e.g. 128 for a depth-7 tree).
	pub fn build(batch_size: usize) -> Result<Self> {
		assert!(
			batch_size.is_power_of_two(),
			"batch_size must be a power of two, got {batch_size}"
		);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		// PI layout: root first, then all leaves.
		let root = HashOutput::add_virtual_hash_public_input(&mut builder);
		let leaves: Vec<MerkleHashTarget<4>> = (0..batch_size)
			.map(|_| HashOutput::add_virtual_hash_public_input(&mut builder))
			.collect();

		// Build Poseidon Merkle tree bottom-up and constrain to root.
		// Direction bit = false → always Poseidon(left || right).
		let f = builder._false();
		let mut nodes = leaves.clone();
		while nodes.len() > 1 {
			let parent_len = nodes.len() >> 1;
			for i in 0..parent_len {
				let left = nodes[2 * i];
				let right = nodes[2 * i + 1];
				nodes[i] = HashOutput::hash_2_to_1_circuit(&mut builder, left, right, f);
			}
			nodes.truncate(parent_len);
		}
		HashOutput::connect_hashes(&mut builder, &nodes[0], &root);

		let targets = SubtreeRootTargets {
			root,
			leaves,
		};
		let circuit_data = builder.build::<ConfigNative>();

		Ok(Self {
			circuit_data,
			targets,
		})
	}

	/// Number of leaves this circuit was built for.
	pub fn batch_size(&self) -> usize {
		self.targets.leaves.len()
	}

	/// Prove that `root = PoseidonMerkle(leaves)`.
	///
	/// The root is computed natively from `leaves` and injected as the
	/// corresponding public input.  `leaves.len()` must equal `batch_size`.
	pub fn prove(&self, leaves: &[HashOutput]) -> Result<ProofNative> {
		assert_eq!(
			leaves.len(),
			self.targets.leaves.len(),
			"leaf count mismatch: expected {}, got {}",
			self.targets.leaves.len(),
			leaves.len()
		);

		let root = Self::compute_root_native(leaves);
		let mut pw = PartialWitness::new();

		HashOutput::set_hash_witness(&mut pw, &self.targets.root, &root)
			.map_err(|e| anyhow!("set root witness: {e}"))?;

		for (target, value) in self.targets.leaves.iter().zip(leaves.iter()) {
			HashOutput::set_hash_witness(&mut pw, target, value)
				.map_err(|e| anyhow!("set leaf witness: {e}"))?;
		}

		self.circuit_data
			.prove(pw)
			.map_err(|e| anyhow!("SubtreeRootCircuit::prove: {e}"))
	}

	/// Compute the Poseidon Merkle root of `leaves` natively.
	///
	/// Matches the in-circuit computation exactly:
	/// `inner_node = Poseidon(left || right)` (direction bit = false).
	pub fn compute_root_native(leaves: &[HashOutput]) -> HashOutput {
		assert!(!leaves.is_empty(), "leaves must not be empty");
		assert!(
			leaves.len().is_power_of_two(),
			"leaves.len() must be a power of two, got {}",
			leaves.len()
		);

		let mut nodes = leaves.to_vec();
		while nodes.len() > 1 {
			let parent_len = nodes.len() >> 1;
			for i in 0..parent_len {
				nodes[i] = HashOutput::hash_2_to_1(&nodes[2 * i], &nodes[2 * i + 1], false);
			}
			nodes.truncate(parent_len);
		}
		nodes[0]
	}

	/// Extract the Merkle root from a proof's public inputs.
	pub fn root_from_proof(proof: &ProofNative) -> HashOutput {
		HashOutput::new(core::array::from_fn(|i| proof.public_inputs[i]))
	}

	/// Extract all leaf values from a proof's public inputs.
	pub fn leaves_from_proof(proof: &ProofNative, batch_size: usize) -> Vec<HashOutput> {
		(0..batch_size)
			.map(|j| HashOutput::new(core::array::from_fn(|k| proof.public_inputs[4 + j * 4 + k])))
			.collect()
	}

	/// Persist the compiled circuit data to `path`.
	pub fn store_artifacts(&self, path: &Path) -> Result<()> {
		fs::create_dir_all(path)?;
		let bytes = self
			.circuit_data
			.to_bytes(&DefaultGateSerializer, &TesseraGeneratorSerializer)
			.map_err(|_| {
				anyhow!(
					"serialize SubtreeRootCircuit failed. \
                     If a new custom generator was added, register it in \
                     tessera-trees/src/groth/serializer.rs."
				)
			})?;
		fs::write(path.join(CIRCUIT_DATA_PATH), bytes)?;
		Ok(())
	}

	/// Reconstruct the circuit from pre-generated artifacts without recompiling.
	///
	/// Replays the builder (deterministic) to recover target wire indices,
	/// then loads the compiled circuit data from disk.
	pub fn from_artifacts(path: &Path, batch_size: usize) -> Result<Self> {
		// Replay builder to recover target wire indices.
		let template = Self::build(batch_size)?;

		let bytes = fs::read(path.join(CIRCUIT_DATA_PATH)).map_err(|e| {
			anyhow!(
				"failed to read '{}': {e}",
				path.join(CIRCUIT_DATA_PATH).display()
			)
		})?;
		let circuit_data = CircuitDataNative::from_bytes(
			&bytes,
			&DefaultGateSerializer,
			&TesseraGeneratorSerializer,
		)
		.map_err(|_| {
			anyhow!(
				"deserialize SubtreeRootCircuit from '{}' failed. \
                 Delete the artifacts directory and rebuild.",
				path.join(CIRCUIT_DATA_PATH).display()
			)
		})?;

		Ok(Self {
			circuit_data,
			targets: template.targets,
		})
	}

	/// Returns `true` if all artifact files are present under `path`.
	pub fn has_artifacts(path: &Path) -> bool {
		path.join(CIRCUIT_DATA_PATH).is_file()
	}
}

// ---------------------------------------------------------------------------
// Tests (Phase C1)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use anyhow::Result;
	use plonky2::field::types::Field;
	use rand::{rngs::StdRng, SeedableRng};
	use tessera_utils::hasher::{MerkleHash, NewRandom};

	use super::*;

	/// Depth-1 tree (2 leaves): verifies both the hash direction and PI layout.
	///
	/// Expected root = Poseidon(leaf0 || leaf1) — NOT Poseidon(leaf1 || leaf0).
	#[test]
	fn test_subtree_root_depth_1() -> Result<()> {
		let leaf0 = HashOutput::new([F::ONE, F::ZERO, F::ZERO, F::ZERO]);
		let leaf1 = HashOutput::new([F::from_canonical_u64(2), F::ZERO, F::ZERO, F::ZERO]);

		let circuit = SubtreeRootCircuit::build(2)?;
		assert_eq!(circuit.batch_size(), 2);
		// root[4] + leaf0[4] + leaf1[4] = 12 PIs
		assert_eq!(circuit.circuit_data.common.num_public_inputs, 12);

		let leaves = [leaf0, leaf1];

		// Cross-check native root against direct hash (direction = false).
		let native_root = SubtreeRootCircuit::compute_root_native(&leaves);
		let expected_root = HashOutput::hash_2_to_1(&leaf0, &leaf1, false);
		let swapped_root = HashOutput::hash_2_to_1(&leaf1, &leaf0, false);
		assert_eq!(native_root, expected_root, "native root mismatch");
		assert_ne!(native_root, swapped_root, "hash direction check failed");

		let proof = circuit.prove(&leaves)?;
		assert_eq!(proof.public_inputs.len(), 12);

		let proof_root = SubtreeRootCircuit::root_from_proof(&proof);
		let proof_leaves = SubtreeRootCircuit::leaves_from_proof(&proof, 2);

		assert_eq!(proof_root, native_root, "circuit root != native root");
		assert_eq!(proof_leaves[0], leaf0, "PI leaf0 mismatch");
		assert_eq!(proof_leaves[1], leaf1, "PI leaf1 mismatch");

		circuit.circuit_data.verify(proof)?;
		Ok(())
	}

	/// Depth-2 tree (4 leaves) with deterministic random leaves.
	#[test]
	fn test_subtree_root_depth_2_random() -> Result<()> {
		let mut rng = StdRng::from_seed([1u8; 32]);
		let leaves: Vec<HashOutput> = (0..4).map(|_| HashOutput::new_random(&mut rng)).collect();

		let circuit = SubtreeRootCircuit::build(4)?;
		let native_root = SubtreeRootCircuit::compute_root_native(&leaves);
		let proof = circuit.prove(&leaves)?;

		assert_eq!(
			SubtreeRootCircuit::root_from_proof(&proof),
			native_root,
			"circuit root != native root"
		);
		circuit.circuit_data.verify(proof)?;
		Ok(())
	}

	/// Full depth-7 tree (128 leaves) — always run with `--release`.
	#[test]
	fn test_subtree_root_depth_7() -> Result<()> {
		let mut rng = StdRng::from_seed([42u8; 32]);
		let leaves: Vec<HashOutput> = (0..128).map(|_| HashOutput::new_random(&mut rng)).collect();

		let circuit = SubtreeRootCircuit::build(128)?;
		assert_eq!(circuit.circuit_data.common.num_public_inputs, (1 + 128) * 4);

		let native_root = SubtreeRootCircuit::compute_root_native(&leaves);
		let proof = circuit.prove(&leaves)?;

		assert_eq!(
			SubtreeRootCircuit::root_from_proof(&proof),
			native_root,
			"circuit root != native root"
		);
		assert_eq!(
			SubtreeRootCircuit::leaves_from_proof(&proof, 128),
			leaves,
			"PI leaves mismatch"
		);
		circuit.circuit_data.verify(proof)?;
		Ok(())
	}

	/// Verify that `compute_root_native` is associative by matching
	/// a manually computed depth-2 tree.
	#[test]
	fn test_compute_root_native_matches_manual() {
		let leaves = [
			HashOutput::new([F::from_canonical_u64(10), F::ZERO, F::ZERO, F::ZERO]),
			HashOutput::new([F::from_canonical_u64(20), F::ZERO, F::ZERO, F::ZERO]),
			HashOutput::new([F::from_canonical_u64(30), F::ZERO, F::ZERO, F::ZERO]),
			HashOutput::new([F::from_canonical_u64(40), F::ZERO, F::ZERO, F::ZERO]),
		];

		let h01 = HashOutput::hash_2_to_1(&leaves[0], &leaves[1], false);
		let h23 = HashOutput::hash_2_to_1(&leaves[2], &leaves[3], false);
		let root = HashOutput::hash_2_to_1(&h01, &h23, false);

		assert_eq!(SubtreeRootCircuit::compute_root_native(&leaves), root);
	}
}
