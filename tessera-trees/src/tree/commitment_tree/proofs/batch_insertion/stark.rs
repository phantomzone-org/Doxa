use anyhow::Result;
use plonky2::{
	field::{
		extension::Extendable,
		types::{Field, PrimeField64},
	},
	hash::hash_types::{HashOutTarget, RichField},
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::circuit_builder::CircuitBuilder,
};

use crate::tree::{
	BatchCommitmentProof,
	hasher::{MerkleHash, MerkleHashCircuit, ToHashOut},
};

pub struct BatchCommitmentProofTargets {
	pub leaves: Vec<HashOutTarget>,
	pub root_old: HashOutTarget,
	pub root_new: HashOutTarget,
	pub start_index: Target,
	pub upper_siblings_old: Vec<HashOutTarget>,
	pub upper_siblings_new: Vec<HashOutTarget>,
}

impl BatchCommitmentProofTargets {
	/// Allocates circuit targets for a batch commitment proof.
	///
	/// # Arguments
	/// * `builder` - The circuit builder
	/// * `depth` - The Merkle tree depth
	/// * `batch_size` - Number of leaves in the batch (must be power of two)
	///
	/// # Public Inputs
	///
	/// `root_old`, `root_new`, and all leaves are exposed directly as public inputs.
	/// Total: `(batch_size + 2) × 4` Goldilocks field elements.
	pub fn new<F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		depth: usize,
		batch_size: usize,
	) -> Self
	where
		F: Field + RichField + Extendable<D>,
	{
		assert!(batch_size.is_power_of_two());

		let log_batch: usize = batch_size.trailing_zeros() as usize;

		Self {
			root_old: builder.add_virtual_hash_public_input(),
			root_new: builder.add_virtual_hash_public_input(),
			leaves: builder.add_virtual_hashes_public_input(batch_size),
			start_index: builder.add_virtual_target(),
			upper_siblings_old: builder.add_virtual_hashes(depth - log_batch),
			upper_siblings_new: builder.add_virtual_hashes(depth - log_batch),
		}
	}

	pub fn connect<H, F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		let f: BoolTarget = builder._false();

		let batch_size: Target = builder.constant(F::from_canonical_u64(self.leaves.len() as u64));
		let new_index: Target = builder.add(self.start_index, batch_size);

		let batch_depth: usize = self.leaves.len().trailing_zeros() as usize;
		let upper_depth: usize = self.upper_siblings_old.len();
		let tree_depth: usize = batch_depth + upper_depth;

		let path: Vec<BoolTarget> = builder.low_bits(self.start_index, tree_depth, tree_depth);

		// Enforce start_index alignment: the lower `batch_depth` bits must be zero
		// This is equivalent to: start_index % batch_size == 0
		let zero = builder.zero();
		for path_elem in path[..batch_depth].iter() {
			builder.connect(path_elem.target, zero);
		}

		// 1) Verifies against old root
		let mut empty_batch_root = builder.constant_hash(H::HEAD);
		for _ in 0..batch_depth {
			empty_batch_root =
				H::hash_2_to_1_circuit(builder, empty_batch_root, empty_batch_root, f) // TODO add specific circuit to avoid bool target
		}

		empty_batch_root = Self::compute_root_circuit::<H, F, D>(
			builder,
			empty_batch_root,
			&self.upper_siblings_old,
			&path[batch_depth..],
			self.start_index,
		);

		builder.connect_hashes(empty_batch_root, self.root_old);

		// 2) Verify against new root
		let mut leaves: Vec<HashOutTarget> = self.leaves.to_vec();

		while leaves.len() > 1 {
			let parent_len = leaves.len() >> 1;
			for i in 0..parent_len {
				let left: HashOutTarget = leaves[2 * i];
				let right: HashOutTarget = leaves[2 * i + 1];
				leaves[i] = H::hash_2_to_1_circuit(builder, left, right, f); // TODO add specific circuit to avoid bool target
			}
			leaves.truncate(parent_len);
		}

		let new_batch_root = Self::compute_root_circuit::<H, F, D>(
			builder,
			leaves[0],
			&self.upper_siblings_new,
			&path[batch_depth..],
			new_index,
		);

		builder.connect_hashes(new_batch_root, self.root_new);
	}

	fn compute_root_circuit<H, F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		leaf_hash: HashOutTarget,
		siblings: &[HashOutTarget],
		path: &[BoolTarget],
		num_leaves: Target,
	) -> HashOutTarget
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		let depth = siblings.len();
		let mut current = leaf_hash;

		assert_eq!(siblings.len(), path.len());

		for (level, (sibling, &dir)) in siblings.iter().zip(path.iter()).enumerate() {
			// At the final level, use hash_root_circuit to commit num_leaves
			if level == depth - 1 {
				// Select left and right based on direction
				let left = HashOutTarget {
					elements: core::array::from_fn(|i| {
						builder.select(dir, sibling.elements[i], current.elements[i])
					}),
				};
				let right = HashOutTarget {
					elements: core::array::from_fn(|i| {
						builder.select(dir, current.elements[i], sibling.elements[i])
					}),
				};
				current = H::hash_root_circuit(builder, num_leaves, left, right);
			} else {
				current = H::hash_2_to_1_circuit(builder, current, *sibling, dir);
			}
		}
		current
	}

	pub fn set<H, F, const DEPTH: usize>(
		&self,
		pw: &mut PartialWitness<F>,
		proof: &BatchCommitmentProof<H>,
	) -> Result<()>
	where
		H: MerkleHash,
		H::Digest: ToHashOut<F>,
		F: Field + PrimeField64,
	{
		assert_eq!(
			self.upper_siblings_new.len(),
			proof.upper_siblings_new.len()
		);
		assert_eq!(
			self.upper_siblings_old.len(),
			proof.upper_siblings_old.len()
		);
		assert_eq!(self.leaves.len(), proof.leaves.len());

		pw.set_hash_target(self.root_new, proof.root_new.to_hash_out())?;
		pw.set_hash_target(self.root_old, proof.root_old.to_hash_out())?;
		pw.set_target(
			self.start_index,
			F::from_canonical_u64(proof.start_index as u64),
		)?;

		for i in 0..self.upper_siblings_new.len() {
			pw.set_hash_target(
				self.upper_siblings_new[i],
				proof.upper_siblings_new[i].to_hash_out(),
			)?;
			pw.set_hash_target(
				self.upper_siblings_old[i],
				proof.upper_siblings_old[i].to_hash_out(),
			)?;
		}

		for i in 0..self.leaves.len() {
			pw.set_hash_target(self.leaves[i], proof.leaves[i].to_hash_out())?;
		}

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use std::time::Instant;

	use anyhow::Result;
	use plonky2::{
		field::goldilocks_field::GoldilocksField,
		iop::witness::PartialWitness,
		plonk::{
			circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
			config::PoseidonGoldilocksConfig,
		},
	};
	use rand::{SeedableRng, rngs::StdRng};

	use crate::tree::{
		BatchCommitmentProofTargets, CommitmentTree,
		hasher::{Hash, NewRandom},
	};

	const D: usize = 2;
	pub type C = PoseidonGoldilocksConfig;
	pub type F = GoldilocksField;

	#[test]
	fn test_batch_insert() -> Result<()> {
		println!("=== Batch Insert Proof (raw PI) ===\n");

		const DEPTH: usize = 32;
		const BATCH_SIZE: usize = 4096;

		print!("Alloc tree 2^{DEPTH}: ");
		let now = Instant::now();
		let mut tree: CommitmentTree<Hash> = CommitmentTree::<Hash>::new(DEPTH);
		println!("{:?}", now.elapsed());

		let mut rng: StdRng = StdRng::from_seed([0u8; 32]);

		print!("Insert batch: ");
		let now = Instant::now();
		let mut leaves: Vec<Hash> = Vec::with_capacity(BATCH_SIZE);
		for _ in 0..BATCH_SIZE {
			leaves.push(Hash::new_random(&mut rng));
		}
		let proof = tree.insert_batch(leaves)?;
		assert!(proof.verify());
		println!("{:?}", now.elapsed());

		// Build the circuit
		let config: CircuitConfig = CircuitConfig::standard_recursion_config();
		let mut builder: CircuitBuilder<F, D> = CircuitBuilder::<F, D>::new(config);

		print!("Alloc Targets: ");
		let now: Instant = Instant::now();
		let targets: BatchCommitmentProofTargets =
			BatchCommitmentProofTargets::new(&mut builder, DEPTH, BATCH_SIZE);
		println!("{:?}", now.elapsed());

		print!("Connect: ");
		let now: Instant = Instant::now();
		targets.connect::<Hash, F, D>(&mut builder);
		println!("{:?}", now.elapsed());

		print!("Set Witnesses: ");
		let now: Instant = Instant::now();
		let mut pw: PartialWitness<GoldilocksField> = PartialWitness::new();
		targets.set::<Hash, F, DEPTH>(&mut pw, &proof)?;
		println!("{:?}", now.elapsed());

		print!("Build: ");
		let now = Instant::now();
		let data = builder.build::<C>();
		println!("{:?}", now.elapsed());

		print!("Prove: ");
		let now = Instant::now();
		let circuit_proof = data.prove(pw)?;
		println!("{:?}", now.elapsed());

		// Raw PI: (batch_size + 2) × 4 = (4096 + 2) × 4 = 16392 field elements
		assert_eq!(circuit_proof.public_inputs.len(), (BATCH_SIZE + 2) * 4);

		let bytes = circuit_proof.to_bytes();
		println!(
			"proof.pi: {}, size: {}KB",
			circuit_proof.public_inputs.len(),
			bytes.len() >> 10
		);

		let proof_compressed = data.compress(circuit_proof)?;
		let bytes = proof_compressed.to_bytes();
		println!("size compressed: {}KB", bytes.len() >> 10);

		print!("Verify: ");
		let now = Instant::now();
		let decompressed = data.decompress(proof_compressed)?;
		data.verify(decompressed)?;
		println!("{:?}", now.elapsed());

		Ok(())
	}
}
