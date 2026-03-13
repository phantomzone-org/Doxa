use anyhow::Result;
use plonky2::{
	field::{
		extension::Extendable,
		types::{Field, PrimeField64},
	},
	hash::hash_types::RichField,
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::circuit_builder::CircuitBuilder,
};

use crate::tree::{
	NullifierInsertProof,
	hasher::{HASH_SIZE, MerkleHashCircuit, MerkleHashTarget},
	utils::{inclusion, populate_inclusion_witness},
};

/// Circuit targets for verifying a *single indexed-Merkle insertion proof*.
///
/// This gadget verifies a *sound root transition*:
///
/// ```text
/// old_root
///   ├─ update predecessor leaf
///   ▼
/// mid_root
///   ├─ insert new node into empty slot
///   ▼
/// new_root
/// ```
///
/// The circuit enforces that:
/// - the predecessor leaf existed in `old_root`
/// - the insertion slot was empty in `old_root`
/// - only the predecessor leaf was updated to obtain `mid_root`
/// - the insertion slot was still empty in `mid_root`
/// - only the insertion slot was updated to obtain `new_root`
/// - the ordering invariant `pred.value < new_value < pred.old_next_value` holds
///
/// No Merkle multiproofs are required.
/// Soundness is achieved by:
/// - reusing identical Merkle paths and siblings across root transitions, and
/// - explicitly re-authenticating an untouched path (the empty slot).
pub struct NullifierInsertProofTargets<const N: usize> {
	// ============================================================
	// Public inputs
	// ============================================================
	/// Merkle root of the tree *before* insertion.
	///
	/// All predecessor and emptiness checks are anchored to this root.
	pub old_root: MerkleHashTarget<N>,

	/// Merkle root of the tree *after* insertion.
	///
	/// This is the final committed root produced by the circuit.
	pub new_root: MerkleHashTarget<N>,

	// ============================================================
	// Private witnesses — predecessor leaf
	// ============================================================
	/// Bit decomposition of the predecessor leaf index.
	///
	/// Interpreted as a little-endian path from leaf → root.
	pub pred_path: Vec<BoolTarget>,

	/// Merkle authentication siblings for the predecessor leaf,
	/// anchored to `old_root`.
	pub pred_siblings: Vec<MerkleHashTarget<N>>,

	/// Value stored in the predecessor leaf.
	pub pred_value: MerkleHashTarget<N>,

	/// Index of the predecessor's successor *before* insertion.
	pub pred_old_next_index: Target,

	/// Value of the predecessor's successor *before* insertion.
	pub pred_old_next_value: MerkleHashTarget<N>,

	// ============================================================
	// Private witnesses — insertion slot / new node
	// ============================================================
	/// Bit decomposition of the insertion index (first empty leaf).
	pub new_node_path: Target,

	/// Value being inserted.
	///
	/// This is public because it defines the nullifier / indexed key.
	pub new_node_value: MerkleHashTarget<N>,

	/// Merkle siblings authenticating that the insertion slot
	/// was empty in `old_root`.
	pub new_node_siblings_before_pred_update: Vec<MerkleHashTarget<N>>,

	/// Merkle siblings authenticating that the insertion slot
	/// remained empty in `mid_root` (after predecessor update).
	pub new_node_siblings_after_pred_update: Vec<MerkleHashTarget<N>>,

	// ============================================================
	// Range-check witnesses for non-membership
	// ============================================================
	/// Witness limbs for `pred_value < new_value`.
	pub u: Vec<Target>,

	/// Witness limbs for `new_value < pred_old_next_value`.
	pub v: Vec<Target>,

	/// Carry bits for the lower-bound comparison.
	pub c_ax: Vec<BoolTarget>,

	/// Carry bits for the upper-bound comparison.
	pub c_xb: Vec<BoolTarget>,
}

impl<const N: usize> NullifierInsertProofTargets<N> {
	/// Allocates all circuit targets required to verify a single insertion.
	///
	/// # Arguments
	/// - `builder`: Plonky2 circuit builder
	/// - `depth`: Merkle tree depth
	/// - `is_first`: whether `old_root` is a public input
	/// - `is_last`: whether `new_root` is a public input
	///
	/// This flexibility allows chaining multiple insertions in one circuit.
	pub fn new<H, F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		depth: usize,
		is_first: bool,
		is_last: bool,
	) -> Self
	where
		H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<N>>,
		F: Field + RichField + Extendable<D>,
	{
		// Roots are public only at the boundaries of a chain
		let old_root = if is_first {
			H::add_virtual_hash_public_input(builder)
		} else {
			H::add_virtual_hash(builder)
		};

		let new_root = if is_last {
			H::add_virtual_hash_public_input(builder)
		} else {
			H::add_virtual_hash(builder)
		};

		// Predecessor witnesses
		let pred_path = (0..depth)
			.map(|_| builder.add_virtual_bool_target_safe())
			.collect();

		let pred_value = H::add_virtual_hash(builder);
		let pred_old_next_index: Target = builder.add_virtual_target();
		let pred_old_next_value = H::add_virtual_hash(builder);
		let pred_siblings: Vec<MerkleHashTarget<N>> =
			(0..depth).map(|_| H::add_virtual_hash(builder)).collect();

		// Insertion witnesses
		let new_node_path: Target = if is_first {
			builder.add_virtual_public_input()
		} else {
			builder.add_virtual_target()
		};

		let new_node_value = H::add_virtual_hash_public_input(builder);

		let new_node_siblings_before_pred_update =
			(0..depth).map(|_| H::add_virtual_hash(builder)).collect();

		let new_node_siblings_after_pred_update =
			(0..depth).map(|_| H::add_virtual_hash(builder)).collect();

		// Range-check witnesses
		let u = (0..2 * HASH_SIZE)
			.map(|_| builder.add_virtual_target())
			.collect();
		let v = (0..2 * HASH_SIZE)
			.map(|_| builder.add_virtual_target())
			.collect();
		let c_ax = (0..2 * HASH_SIZE - 1)
			.map(|_| builder.add_virtual_bool_target_safe())
			.collect();
		let c_xb = (0..2 * HASH_SIZE - 1)
			.map(|_| builder.add_virtual_bool_target_safe())
			.collect();

		Self {
			old_root,
			new_root,
			pred_path,
			pred_value,
			pred_old_next_index,
			pred_old_next_value,
			new_node_path,
			new_node_value,
			pred_siblings,
			new_node_siblings_before_pred_update,
			new_node_siblings_after_pred_update,
			u,
			v,
			c_ax,
			c_xb,
		}
	}

	/// Allocates all circuit targets as private witnesses.
	///
	/// This is used with commitment-based proofs where all inputs are hashed
	/// and only the commitment is public.
	pub fn new_all_private<H, F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		depth: usize,
	) -> Self
	where
		H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<N>>,
		F: Field + RichField + Extendable<D>,
	{
		// All targets are private
		let old_root = H::add_virtual_hash(builder);
		let new_root = H::add_virtual_hash(builder);

		// Predecessor witnesses
		let pred_path = (0..depth)
			.map(|_| builder.add_virtual_bool_target_safe())
			.collect();

		let pred_value = H::add_virtual_hash(builder);
		let pred_old_next_index: Target = builder.add_virtual_target();
		let pred_old_next_value = H::add_virtual_hash(builder);
		let pred_siblings: Vec<MerkleHashTarget<N>> =
			(0..depth).map(|_| H::add_virtual_hash(builder)).collect();

		// Insertion witnesses - all private
		let new_node_path: Target = builder.add_virtual_target();
		let new_node_value = H::add_virtual_hash(builder);

		let new_node_siblings_before_pred_update =
			(0..depth).map(|_| H::add_virtual_hash(builder)).collect();

		let new_node_siblings_after_pred_update =
			(0..depth).map(|_| H::add_virtual_hash(builder)).collect();

		// Range-check witnesses
		let u = (0..2 * HASH_SIZE)
			.map(|_| builder.add_virtual_target())
			.collect();
		let v = (0..2 * HASH_SIZE)
			.map(|_| builder.add_virtual_target())
			.collect();
		let c_ax = (0..2 * HASH_SIZE - 1)
			.map(|_| builder.add_virtual_bool_target_safe())
			.collect();
		let c_xb = (0..2 * HASH_SIZE - 1)
			.map(|_| builder.add_virtual_bool_target_safe())
			.collect();

		Self {
			old_root,
			new_root,
			pred_path,
			pred_value,
			pred_old_next_index,
			pred_old_next_value,
			new_node_path,
			new_node_value,
			pred_siblings,
			new_node_siblings_before_pred_update,
			new_node_siblings_after_pred_update,
			u,
			v,
			c_ax,
			c_xb,
		}
	}

	/// Returns the Merkle tree depth implied by the allocated witnesses.
	pub fn depth(&self) -> usize {
		self.pred_siblings.len()
	}

	/// Connects all constraints enforcing a *sound indexed-Merkle insertion*.
	///
	/// This method mirrors `InsertProof::verify()` exactly, but in-circuit.
	///
	/// The key invariant enforced is:
	/// > each root transition reuses the same Merkle path and siblings,
	/// > differing only in the leaf hash.
	pub fn connect<H, F, const D: usize>(
		&self,
		builder: &mut CircuitBuilder<F, D>,
		ctx: &H::CircuitContext,
	) where
		H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<N>>,
		F: Field + RichField + Extendable<D>,
	{
		// Empty leaf hash.
		//
		// IMPORTANT: must match the native tree's empty leaf representation.
		let head = H::constant_hash(builder, &H::HEAD);
		let depth = self.depth();

		// new_node_path (index) == new_node_path
		let node_path_bits: Vec<BoolTarget> = builder.low_bits(self.new_node_path, depth, depth);
		let num_leaves_new: Target = builder.add_const(self.new_node_path, F::ONE);

		// ------------------------------------------------------------
		// 1. Authenticate predecessor in old_root
		// ------------------------------------------------------------
		let old_pred_hash = H::commit_node_circuit(
			builder,
			ctx,
			self.pred_value,
			self.pred_old_next_index,
			self.pred_old_next_value,
		);
		let computed_old_root_from_pred = Self::compute_root_circuit::<H, F, D>(
			builder,
			ctx,
			old_pred_hash,
			&self.pred_siblings,
			&self.pred_path,
			self.new_node_path,
		);
		H::connect_hashes(builder, &computed_old_root_from_pred, &self.old_root);

		// ------------------------------------------------------------
		// 2. Authenticate emptiness in old_root
		// ------------------------------------------------------------
		let computed_old_root_from_empty = Self::compute_root_circuit::<H, F, D>(
			builder,
			ctx,
			head,
			&self.new_node_siblings_before_pred_update,
			&node_path_bits,
			self.new_node_path,
		);
		H::connect_hashes(builder, &computed_old_root_from_empty, &self.old_root);

		// ------------------------------------------------------------
		// 3. Update predecessor → mid_root
		// Tree size hasn't changed yet (just updating existing node).
		// ------------------------------------------------------------
		let new_pred_hash = H::commit_node_circuit(
			builder,
			ctx,
			self.pred_value,
			self.new_node_path,
			self.new_node_value,
		);
		let mid_root = Self::compute_root_circuit::<H, F, D>(
			builder,
			ctx,
			new_pred_hash,
			&self.pred_siblings,
			&self.pred_path,
			self.new_node_path,
		);

		// ------------------------------------------------------------
		// 4. Re-authenticate emptiness in mid_root
		// Still using new_node_path since no new node inserted yet.
		// ------------------------------------------------------------
		let computed_mid_root = Self::compute_root_circuit::<H, F, D>(
			builder,
			ctx,
			head,
			&self.new_node_siblings_after_pred_update,
			&node_path_bits,
			self.new_node_path,
		);
		H::connect_hashes(builder, &computed_mid_root, &mid_root);

		// ------------------------------------------------------------
		// 5. Insert new node → new_root
		// Now tree size increases to num_leaves_new.
		// ------------------------------------------------------------
		let new_node_hash = H::commit_node_circuit(
			builder,
			ctx,
			self.new_node_value,
			self.pred_old_next_index,
			self.pred_old_next_value,
		);
		let computed_new_root = Self::compute_root_circuit::<H, F, D>(
			builder,
			ctx,
			new_node_hash,
			&self.new_node_siblings_after_pred_update,
			&node_path_bits,
			num_leaves_new,
		);
		H::connect_hashes(builder, &computed_new_root, &self.new_root);

		// ------------------------------------------------------------
		// 6. Range / non-membership constraint
		// ------------------------------------------------------------
		inclusion(
			builder,
			&self.pred_value.elements,
			&self.new_node_value.elements,
			&self.pred_old_next_value.elements,
			&self.u,
			&self.v,
			&self.c_ax,
			&self.c_xb,
		);
	}

	/// Computes a Merkle root from a leaf hash and its authentication path.
	///
	/// The path bits are interpreted as little-endian:
	/// bit `i` indicates left/right at depth `i`.
	///
	/// At the final level, uses `hash_root_circuit` to commit `num_leaves`.
	fn compute_root_circuit<H, F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		ctx: &H::CircuitContext,
		leaf_hash: MerkleHashTarget<N>,
		siblings: &[MerkleHashTarget<N>],
		path: &[BoolTarget],
		num_leaves: Target,
	) -> MerkleHashTarget<N>
	where
		H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<N>>,
		F: Field + RichField + Extendable<D>,
	{
		let depth = siblings.len();
		let mut current = leaf_hash;

		for (level, (sibling, &dir)) in siblings.iter().zip(path.iter()).enumerate() {
			// At the final level, use hash_root_circuit to commit num_leaves
			if level == depth - 1 {
				// Select left and right based on direction
				let left = MerkleHashTarget::<N>::select(builder, dir, sibling, &current);
				let right = MerkleHashTarget::<N>::select(builder, dir, &current, sibling);
				current = H::hash_root_circuit(builder, ctx, num_leaves, left, right);
			} else {
				current = H::hash_2_to_1_circuit(builder, ctx, current, *sibling, dir);
			}
		}
		current
	}

	/// Populates all witnesses from a native `InsertProof`.
	///
	/// This method assumes:
	/// - identical bit ordering between native and circuit paths
	/// - identical empty-leaf hash
	pub fn set<H, F, const D: usize, const DEPTH: usize>(
		&self,
		pw: &mut PartialWitness<F>,
		proof: &NullifierInsertProof<H>,
	) -> Result<()>
	where
		H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<N>>,
		F: Field + PrimeField64 + RichField + Extendable<D>,
	{
		assert_eq!(
			proof.depth(),
			self.depth(),
			"Proof depth must match target depth"
		);

		// Public inputs
		H::set_hash_witness(pw, &self.old_root, &proof.old_root)?;
		H::set_hash_witness(pw, &self.new_root, &proof.new_root)?;

		// Predecessor node data
		H::set_hash_witness(pw, &self.pred_value, &proof.pred_value)?;
		pw.set_target(
			self.pred_old_next_index,
			F::from_canonical_u64(proof.pred_old_next_index as u64),
		)?;
		H::set_hash_witness(pw, &self.pred_old_next_value, &proof.pred_old_next_value)?;
		for (i, sibling) in proof.pred_old_siblings.iter().enumerate() {
			H::set_hash_witness(pw, &self.pred_siblings[i], sibling)?;
			pw.set_bool_target(self.pred_path[i], ((proof.pred_path >> i) & 1) == 1)?;
		}

		// New node data
		H::set_hash_witness(pw, &self.new_node_value, &proof.new_node_value)?;
		for i in 0..DEPTH {
			H::set_hash_witness(
				pw,
				&self.new_node_siblings_before_pred_update[i],
				&proof.new_node_siblings_before_pred_update[i],
			)?;
			H::set_hash_witness(
				pw,
				&self.new_node_siblings_after_pred_update[i],
				&proof.new_node_siblings_after_pred_update[i],
			)?;
		}

		pw.set_target(
			self.new_node_path,
			F::from_canonical_u64(proof.new_node_path as u64),
		)?;

		// Range check witnesses for non-membership
		populate_inclusion_witness(
			pw,
			H::digest_elements(&proof.pred_value),
			H::digest_elements(&proof.new_node_value),
			H::digest_elements(&proof.pred_old_next_value),
			&self.u,
			&self.v,
			&self.c_ax,
			&self.c_xb,
		)?;

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

	use crate::tree::{
		NullifierInsertProofTargets, NullifierTree,
		hasher::{HashOutput, MerkleHashCircuit, NewFromU64},
	};

	const D: usize = 2;
	pub type C = PoseidonGoldilocksConfig;
	pub type F = GoldilocksField;

	#[test]
	fn insert_proof_circuit() -> Result<()> {
		const DEPTH: usize = 32;

		print!("Alloc tree 2^{DEPTH}: ");
		let now = Instant::now();
		let mut tree: NullifierTree<HashOutput> = NullifierTree::<HashOutput>::new(DEPTH);
		println!("{:?}", now.elapsed());

		// Insert a value to get a valid proof
		print!("Insert value: ");
		let now = Instant::now();
		let value = HashOutput::new_from_u64(42);
		let proof = tree.insert(value)?;
		println!("{:?}", now.elapsed());

		// Verify the proof natively first
		print!("Native verify: ");
		let now = Instant::now();
		assert!(proof.verify(), "Native proof verification failed");
		println!("{:?}", now.elapsed());

		// Build the circuit
		let config = CircuitConfig::standard_recursion_config();
		let mut builder: CircuitBuilder<F, D> = CircuitBuilder::<F, D>::new(config);

		let ctx = HashOutput::register_luts(&mut builder);

		print!("Alloc Targets: ");
		let now = Instant::now();
		let targets =
			NullifierInsertProofTargets::new::<HashOutput, F, D>(&mut builder, DEPTH, true, true);
		println!("{:?}", now.elapsed());

		print!("Connect: ");
		let now = Instant::now();
		targets.connect::<HashOutput, F, D>(&mut builder, &ctx);
		println!("{:?}", now.elapsed());

		print!("Set Witnesses: ");
		let now = Instant::now();
		let mut pw = PartialWitness::new();
		targets.set::<HashOutput, F, D, DEPTH>(&mut pw, &proof)?;
		println!("{:?}", now.elapsed());

		print!("Build: ");
		let now = Instant::now();
		let data = builder.build::<C>();
		println!("{:?}", now.elapsed());

		print!("Prove: ");
		let now = Instant::now();
		let circuit_proof = data.prove(pw)?;
		println!("{:?}", now.elapsed());

		println!("proof.pi: {}", circuit_proof.public_inputs.len());
		let bytes = circuit_proof.to_bytes();
		println!("size: {}KB", bytes.len() >> 10);

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
