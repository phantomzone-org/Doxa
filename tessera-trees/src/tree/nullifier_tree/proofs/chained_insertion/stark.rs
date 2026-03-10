//! STARK circuit for chained insertion proofs.
//!
//! This module provides circuit targets and a proof generator for verifying
//! multiple chained insertions in a single circuit.
//!
//! ## Design Overview
//!
//! The circuit chains N single insertion proof circuits together:
//! - Each insertion circuit verifies: old_root_i → new_root_i
//! - Chain constraints connect: new_root_i == old_root_{i+1}
//! - Private witnesses: intermediate roots and all proof data
//!
//! ## Public Inputs
//!
//! `old_root`, `new_node_path` (starting index), all inserted values, and
//! `new_root` are exposed directly.
//! Total: `4 × batch_size + 9` Goldilocks field elements.
//!
//! ## Complexity
//!
//! For a batch of K insertions with tree depth D:
//! - Gates: O(K × D) - linear in batch size
//! - Constraints per insertion: ~4 Merkle paths + 2 range checks
//! - Total: 4KD hash operations + 2K range checks

use anyhow::{Result, anyhow};
use plonky2::{
	field::{
		extension::Extendable,
		types::{Field, PrimeField64},
	},
	hash::hash_types::RichField,
	iop::{target::Target, witness::PartialWitness},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{CircuitConfig, CircuitData},
		config::{AlgebraicHasher, GenericConfig},
		proof::ProofWithPublicInputs,
	},
};

use crate::tree::{
	NullifierChainedInsertProof, NullifierInsertProofTargets,
	error::MerkleTreeError,
	hasher::{MerkleHash, MerkleHashCircuit, ToHashOut},
};

/// Circuit targets for verifying a chained insertion proof.
///
/// This structure holds targets for multiple insertions and connects them
/// with chaining constraints.
pub struct ChainedInsertProofTargets {
	/// Targets for each individual insertion
	insertions: Vec<NullifierInsertProofTargets>,
	/// Tree depth
	depth: usize,
}

impl ChainedInsertProofTargets {
	/// Allocates circuit targets for a chained insertion proof.
	///
	/// # Arguments
	/// * `builder` - The circuit builder
	/// * `depth` - The Merkle tree depth
	/// * `batch_size` - The number of insertions in the chain
	///
	/// # Public Inputs
	///
	/// `old_root[4]`, `new_node_path[1]` (starting chain index), all inserted
	/// `values[batch_size × 4]`, and `new_root[4]` are exposed directly.
	/// Total: `4 × batch_size + 9` Goldilocks field elements.
	pub fn new<F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		depth: usize,
		batch_size: usize,
	) -> Self
	where
		F: Field + RichField + Extendable<D>,
	{
		assert!(batch_size > 0, "batch_size must be at least 1");

		let insertions: Vec<NullifierInsertProofTargets> = (0..batch_size)
			.map(|i| NullifierInsertProofTargets::new(builder, depth, i == 0, i == batch_size - 1))
			.collect();

		Self {
			insertions,
			depth,
		}
	}

	/// Returns the number of insertions this circuit handles.
	pub fn batch_size(&self) -> usize {
		self.insertions.len()
	}

	/// Returns the tree depth.
	pub fn depth(&self) -> usize {
		self.depth
	}

	/// Connects all constraints including chaining.
	///
	/// This connects:
	/// 1. Each individual insertion proof's constraints
	/// 2. Chaining constraints: new_root[i] == old_root[i+1]
	/// 3. Chaining constraints: index[i]+1 == index[i+1]
	pub fn connect<H, F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		// Connect individual insertion constraints
		for insertion in &self.insertions {
			insertion.connect::<H, F, D>(builder);
		}

		let one: Target = builder.one();

		// Connect chaining constraints
		for i in 0..self.insertions.len() - 1 {
			// Root chaining: new_root[i] == old_root[i+1]
			builder.connect_hashes(self.insertions[i].new_root, self.insertions[i + 1].old_root);

			// num_leaves chaining: index[i]+1 == index[i+1]
			let next_node_path = builder.add(self.insertions[i].new_node_path, one);
			builder.connect(next_node_path, self.insertions[i + 1].new_node_path);
		}
	}

	/// Sets all witness values from a ChainedInsertProof.
	pub fn set<H, F, const DEPTH: usize>(
		&self,
		pw: &mut PartialWitness<F>,
		proof: &NullifierChainedInsertProof<H>,
	) -> Result<()>
	where
		H: MerkleHash,
		H::Digest: ToHashOut<F>,
		F: Field + PrimeField64,
	{
		assert_eq!(
			proof.len(),
			self.batch_size(),
			"Proof size {} doesn't match circuit batch size {}",
			proof.len(),
			self.batch_size()
		);
		assert_eq!(
			DEPTH, self.depth,
			"Proof depth {} doesn't match circuit depth {}",
			DEPTH, self.depth
		);

		for (i, insertion_targets) in self.insertions.iter().enumerate() {
			insertion_targets.set::<H, F, DEPTH>(pw, &proof.proofs[i])?;
		}

		Ok(())
	}
}

/// A reusable STARK proof generator for chained insertions.
///
/// This struct holds a pre-built circuit that can be reused to generate
/// STARK proofs for chained insertions of a fixed batch size.
pub struct ChainedInsertProofGenerator<
	H: MerkleHash + MerkleHashCircuit<F, D>,
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
	const D: usize,
	const DEPTH: usize,
	const BATCH_SIZE: usize,
> where
	<H as MerkleHash>::Digest: ToHashOut<F>,
{
	/// The pre-built circuit data
	pub circuit_data: CircuitData<F, C, D>,
	/// The circuit targets
	targets: ChainedInsertProofTargets,
	/// Phantom data for the hash type
	_phantom: std::marker::PhantomData<H>,
}

impl<H, F, C, const D: usize, const DEPTH: usize, const BATCH_SIZE: usize>
	ChainedInsertProofGenerator<H, F, C, D, DEPTH, BATCH_SIZE>
where
	H: MerkleHash + MerkleHashCircuit<F, D>,
	<H as MerkleHash>::Digest: ToHashOut<F>,
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
	C::Hasher: AlgebraicHasher<F>,
{
	/// Creates a new proof generator with default circuit configuration.
	pub fn new() -> Self {
		Self::with_config(CircuitConfig::standard_recursion_config())
	}

	/// Creates a new proof generator with a custom circuit configuration.
	pub fn with_config(config: CircuitConfig) -> Self {
		let mut builder = CircuitBuilder::<F, D>::new(config);

		// Allocate targets
		let targets = ChainedInsertProofTargets::new(&mut builder, DEPTH, BATCH_SIZE);

		// Connect constraints
		targets.connect::<H, F, D>(&mut builder);

		// Build the circuit
		let circuit_data = builder.build::<C>();

		Self {
			circuit_data,
			targets,
			_phantom: std::marker::PhantomData,
		}
	}

	/// Generates a STARK proof from a chained insertion proof.
	pub fn prove(
		&self,
		proof: &NullifierChainedInsertProof<H>,
	) -> Result<ProofWithPublicInputs<F, C, D>> {
		if proof.depth() != DEPTH {
			return Err(anyhow!(MerkleTreeError::DepthMismatch(format!(
				"DepthMismatch: {} != {DEPTH}",
				proof.depth()
			))));
		}
		let mut pw = PartialWitness::new();
		self.targets.set::<H, F, DEPTH>(&mut pw, proof)?;
		let circuit_proof = self.circuit_data.prove(pw)?;
		Ok(circuit_proof)
	}

	/// Verifies a STARK proof generated by this generator.
	pub fn verify(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<()> {
		self.circuit_data.verify(proof.clone())?;
		Ok(())
	}

	/// Returns the common circuit data (needed for aggregation).
	pub fn common_data(&self) -> &plonky2::plonk::circuit_data::CommonCircuitData<F, D> {
		&self.circuit_data.common
	}

	/// Returns the verifier-only circuit data (needed for aggregation).
	pub fn verifier_data(&self) -> &plonky2::plonk::circuit_data::VerifierOnlyCircuitData<C, D> {
		&self.circuit_data.verifier_only
	}

	/// Returns the batch size this generator was built for.
	pub fn batch_size(&self) -> usize {
		BATCH_SIZE
	}

	/// Returns the tree depth this generator was built for.
	pub fn depth(&self) -> usize {
		DEPTH
	}
}

impl<H, F, C, const D: usize, const DEPTH: usize, const BATCH_SIZE: usize> Default
	for ChainedInsertProofGenerator<H, F, C, D, DEPTH, BATCH_SIZE>
where
	H: MerkleHash + MerkleHashCircuit<F, D>,
	<H as MerkleHash>::Digest: ToHashOut<F>,
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
	C::Hasher: AlgebraicHasher<F>,
{
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod test {
	use std::time::Instant;

	use anyhow::Result;
	use plonky2::{
		field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
	};

	use super::ChainedInsertProofGenerator;
	use crate::tree::{
		NullifierChainedInsertProof, NullifierTree,
		hasher::{Hash, NewFromU64},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = GoldilocksField;

	#[test]
	fn test_chained_insert() -> Result<()> {
		println!("=== Chained Insert Proof (raw PI) ===\n");

		const DEPTH: usize = 32;
		const BATCH_SIZE: usize = 64;

		let mut tree: NullifierTree<Hash> = NullifierTree::new(DEPTH);

		print!("Generating {} insertion proofs: ", BATCH_SIZE);
		let now = Instant::now();
		let mut proofs = Vec::with_capacity(BATCH_SIZE);
		for i in 0..BATCH_SIZE {
			let value = HashOutput::new_from_u64((i + 1) as u64 * 1000);
			let proof = tree.insert(value)?;
			proofs.push(proof);
		}
		println!("{:?}", now.elapsed());

		let chained_proof = NullifierChainedInsertProof::new(proofs);

		print!("Verify native proof: ");
		let now = Instant::now();
		assert!(chained_proof.verify(), "Native verification failed");
		println!("{:?}", now.elapsed());

		print!("Build circuit: ");
		let now = Instant::now();
		let generator = ChainedInsertProofGenerator::<Hash, F, C, D, DEPTH, BATCH_SIZE>::new();
		println!("{:?}", now.elapsed());

		print!("Generate STARK proof: ");
		let now = Instant::now();
		let stark_proof = generator.prove(&chained_proof)?;
		println!("{:?}", now.elapsed());

		// Raw PI layout: old_root[4] + new_node_path[1] + values[BATCH_SIZE×4] + new_root[4]
		// = 4*BATCH_SIZE + 9 = 265
		assert_eq!(stark_proof.public_inputs.len(), 4 * BATCH_SIZE + 9);

		print!("Verify STARK proof: ");
		let now = Instant::now();
		generator.verify(&stark_proof)?;
		println!("{:?}", now.elapsed());

		println!("\nPublic inputs: {}", stark_proof.public_inputs.len());
		println!("Proof size: {}KB", stark_proof.to_bytes().len() >> 10);

		println!("\n=== Test Passed! ===");
		Ok(())
	}
}
