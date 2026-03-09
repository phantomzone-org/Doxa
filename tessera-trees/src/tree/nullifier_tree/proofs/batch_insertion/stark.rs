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

use super::BatchInsertProof;
use crate::tree::{
	hasher::{HASH_SIZE, MerkleHash, MerkleHashCircuit, ToHashOut},
	utils::{inclusion, populate_inclusion_witness},
};

/// Top-level circuit targets for the batch nullifier insertion proof.
pub struct BatchNullifierInsertProofTargets {
	// Public inputs
	pub old_root: HashOutTarget,
	pub new_root: HashOutTarget,
	pub start_index: Target,

	// Per-leaf links
	pub links: Vec<BatchInsertionLinkTargets>,

	// Upper siblings for batch subtree → new_root walk (depth - log_batch_size)
	pub upper_siblings_after_pred_update: Vec<HashOutTarget>,
}

impl BatchNullifierInsertProofTargets {
	pub fn new<F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		depth: usize,
		batch_size: usize,
	) -> Self
	where
		F: Field + RichField + Extendable<D>,
	{
		assert!(batch_size.is_power_of_two());
		let log_batch = batch_size.trailing_zeros() as usize;
		let upper_depth = depth - log_batch;

		let old_root = builder.add_virtual_hash_public_input();
		let new_root = builder.add_virtual_hash_public_input();

		let links: Vec<BatchInsertionLinkTargets> = (0..batch_size)
			.map(|_| BatchInsertionLinkTargets::new(builder, depth))
			.collect();

		// Register leaf values as public inputs (after old_root, new_root)
		for link in &links {
			builder.register_public_inputs(&link.leaf_value.elements);
		}

		Self {
			old_root,
			new_root,
			start_index: builder.add_virtual_target(),

			links,

			upper_siblings_after_pred_update: builder.add_virtual_hashes(upper_depth),
		}
	}

	pub fn batch_size(&self) -> usize {
		self.links.len()
	}

	/// Connects all phases (A, B, C) of the batch insertion proof.
	pub fn connect<H, F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		self.connect_phase_a::<H, F, D>(builder);
		self.connect_phase_b::<H, F, D>(builder);
		self.connect_phase_c::<H, F, D>(builder);
	}

	/// Connects Phase A constraints: old_root → mid_root (predecessor updates).
	///
	/// Returns mid_root for use in subsequent phases.
	pub fn connect_phase_a<H, F, const D: usize>(
		&self,
		builder: &mut CircuitBuilder<F, D>,
	) -> HashOutTarget
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		// Derive mid_root from link[0]'s pred_new authentication.
		// This also constrains link[0]'s pred_new path, so we skip it below.
		let mid_root = self.links[0].compute_mid_root::<H, F, D>(builder, self.start_index);

		// All links: authenticate pred_old against old_root
		for link in &self.links {
			link.connect_pred_old_auth::<H, F, D>(builder, self.old_root, self.start_index);
		}

		// Links[1..]: authenticate pred_new against mid_root
		// (link[0] is skipped — its pred_new auth is tautological with compute_mid_root)
		for link in &self.links[1..] {
			link.connect_pred_new_auth::<H, F, D>(builder, mid_root, self.start_index);
		}

		mid_root
	}

	/// Connects Phase B: linked-list constraints.
	pub fn connect_phase_b<H, F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		let batch_size = self.batch_size();

		self.links[0].connect_first_link(builder);

		for link in &self.links {
			link.connect_link_constraints::<H, F, D>(builder);
		}

		for i in 0..batch_size - 1 {
			self.links[i].connect_transition_constraints(builder, &self.links[i + 1]);
		}

		self.links[batch_size - 1].connect_last_link(builder);
	}

	/// Connects Phase C: batch subtree → new_root.
	pub fn connect_phase_c<H, F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		let batch_size = self.batch_size();
		let log_batch = batch_size.trailing_zeros() as usize;
		let depth = self.links[0].depth();
		let upper_depth = depth - log_batch;

		let f = builder._false();

		// Derive upper path bits from start_index
		let path_bits: Vec<BoolTarget> = builder.low_bits(self.start_index, depth, depth);
		let upper_path = &path_bits[log_batch..];

		// Enforce start_index alignment: lower log_batch bits must be zero
		let zero = builder.zero();
		for bit in &path_bits[..log_batch] {
			builder.connect(bit.target, zero);
		}

		// num_leaves for new tree = start_index + batch_size
		let batch_size_target = builder.constant(F::from_canonical_u64(batch_size as u64));
		let new_num_leaves = builder.add(self.start_index, batch_size_target);

		// ============================================================
		// Build batch subtree and derive new_root
		// ============================================================

		// Compute leaf hashes
		let mut level: Vec<HashOutTarget> = self
			.links
			.iter()
			.map(|link| link.leaf_hash_circuit::<H, F, D>(builder))
			.collect();

		// Build subtree bottom-up
		for _ in 0..log_batch {
			let parent_len = level.len() >> 1;
			for j in 0..parent_len {
				level[j] = H::hash_2_to_1_circuit(builder, level[2 * j], level[2 * j + 1], f);
			}
			level.truncate(parent_len);
		}

		let batch_subtree_root = level[0];

		// Walk subtree root through upper siblings to new_root
		let computed_new_root = Self::compute_upper_root_circuit::<H, F, D>(
			builder,
			batch_subtree_root,
			&self.upper_siblings_after_pred_update,
			&upper_path[..upper_depth],
			new_num_leaves,
		);
		builder.connect_hashes(computed_new_root, self.new_root);
	}

	/// Computes a subtree root up through upper siblings to the tree root.
	fn compute_upper_root_circuit<H, F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		subtree_root: HashOutTarget,
		upper_siblings: &[HashOutTarget],
		upper_path: &[BoolTarget],
		num_leaves: Target,
	) -> HashOutTarget
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		BatchInsertionLinkTargets::compute_root_circuit::<H, F, D>(
			builder,
			subtree_root,
			upper_siblings,
			upper_path,
			num_leaves,
		)
	}

	/// Populates all witnesses from a native `BatchInsertProof`.
	pub fn set<H, F, const DEPTH: usize>(
		&self,
		pw: &mut PartialWitness<F>,
		proof: &BatchInsertProof<H>,
	) -> Result<()>
	where
		H: MerkleHash,
		H::Digest: ToHashOut<F>,
		F: Field + PrimeField64,
	{
		let batch_size = self.links.len();
		assert_eq!(proof.links.len(), batch_size);

		// Public inputs
		pw.set_hash_target(self.old_root, proof.old_root.to_hash_out())?;
		pw.set_hash_target(self.new_root, proof.new_root.to_hash_out())?;
		pw.set_target(
			self.start_index,
			F::from_canonical_u64(proof.start_index as u64),
		)?;

		// Upper siblings
		for (i, target) in self.upper_siblings_after_pred_update.iter().enumerate() {
			pw.set_hash_target(
				*target,
				proof.new_node_upper_siblings_after_pred_update[i].to_hash_out(),
			)?;
		}

		// Per-link witnesses
		for (link_targets, link) in self.links.iter().zip(proof.links.iter()) {
			link_targets.set(pw, link)?;
		}

		Ok(())
	}
}

/// Circuit targets for a single link (row) of the batch insertion trace.
pub struct BatchInsertionLinkTargets {
	pub mask: BoolTarget,

	// New leaf
	pub leaf_index: Target,
	pub leaf_value: HashOutTarget,
	pub leaf_next_index: Target,
	pub leaf_next_value: HashOutTarget,

	// Predecessor
	pub pred_path: Vec<BoolTarget>,
	pub pred_value: HashOutTarget,
	pub pred_old_next_index: Target,
	pub pred_old_next_value: HashOutTarget,
	pub pred_new_next_index: Target,
	pub pred_new_next_value: HashOutTarget,
	pub pred_old_siblings: Vec<HashOutTarget>,
	pub pred_new_siblings: Vec<HashOutTarget>,

	// Range-check witnesses for pred_value < leaf_value < pred_old_next_value
	pub u: Vec<Target>,
	pub v: Vec<Target>,
	pub c_ax: Vec<BoolTarget>,
	pub c_xb: Vec<BoolTarget>,
}

impl BatchInsertionLinkTargets {
	pub fn new<F, const D: usize>(builder: &mut CircuitBuilder<F, D>, depth: usize) -> Self
	where
		F: Field + RichField + Extendable<D>,
	{
		Self {
			mask: builder.add_virtual_bool_target_safe(),

			leaf_index: builder.add_virtual_target(),
			leaf_value: builder.add_virtual_hash(),
			leaf_next_index: builder.add_virtual_target(),
			leaf_next_value: builder.add_virtual_hash(),

			pred_path: (0..depth)
				.map(|_| builder.add_virtual_bool_target_safe())
				.collect(),
			pred_value: builder.add_virtual_hash(),
			pred_old_next_index: builder.add_virtual_target(),
			pred_old_next_value: builder.add_virtual_hash(),
			pred_new_next_index: builder.add_virtual_target(),
			pred_new_next_value: builder.add_virtual_hash(),
			pred_old_siblings: (0..depth).map(|_| builder.add_virtual_hash()).collect(),
			pred_new_siblings: (0..depth).map(|_| builder.add_virtual_hash()).collect(),

			u: (0..2 * HASH_SIZE)
				.map(|_| builder.add_virtual_target())
				.collect(),
			v: (0..2 * HASH_SIZE)
				.map(|_| builder.add_virtual_target())
				.collect(),
			c_ax: (0..2 * HASH_SIZE - 1)
				.map(|_| builder.add_virtual_bool_target_safe())
				.collect(),
			c_xb: (0..2 * HASH_SIZE - 1)
				.map(|_| builder.add_virtual_bool_target_safe())
				.collect(),
		}
	}

	pub fn depth(&self) -> usize {
		self.pred_old_siblings.len()
	}

	// ================================================================
	// Phase A: Merkle root authentication
	// ================================================================

	/// Derives mid_root from this link's pred_new authentication path.
	pub fn compute_mid_root<H, F, const D: usize>(
		&self,
		builder: &mut CircuitBuilder<F, D>,
		num_leaves: Target,
	) -> HashOutTarget
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		let pred_new_hash = H::commit_node_circuit(
			builder,
			self.pred_value,
			self.pred_new_next_index,
			self.pred_new_next_value,
		);
		Self::compute_root_circuit::<H, F, D>(
			builder,
			pred_new_hash,
			&self.pred_new_siblings,
			&self.pred_path,
			num_leaves,
		)
	}

	/// Authenticates this link's old predecessor against old_root.
	pub fn connect_pred_old_auth<H, F, const D: usize>(
		&self,
		builder: &mut CircuitBuilder<F, D>,
		old_root: HashOutTarget,
		num_leaves: Target,
	) where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		let old_pred_hash = H::commit_node_circuit(
			builder,
			self.pred_value,
			self.pred_old_next_index,
			self.pred_old_next_value,
		);
		let computed_old_root = Self::compute_root_circuit::<H, F, D>(
			builder,
			old_pred_hash,
			&self.pred_old_siblings,
			&self.pred_path,
			num_leaves,
		);
		builder.connect_hashes(computed_old_root, old_root);
	}

	/// Authenticates this link's new predecessor against mid_root.
	pub fn connect_pred_new_auth<H, F, const D: usize>(
		&self,
		builder: &mut CircuitBuilder<F, D>,
		mid_root: HashOutTarget,
		num_leaves: Target,
	) where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		let new_pred_hash = H::commit_node_circuit(
			builder,
			self.pred_value,
			self.pred_new_next_index,
			self.pred_new_next_value,
		);
		let computed_mid_root = Self::compute_root_circuit::<H, F, D>(
			builder,
			new_pred_hash,
			&self.pred_new_siblings,
			&self.pred_path,
			num_leaves,
		);
		builder.connect_hashes(computed_mid_root, mid_root);
	}

	// ================================================================
	// Phase B: Linked-list constraints
	// ================================================================

	/// Per-link constraints (independent of neighbors).
	///
	/// - Constraint 5: pred_value < leaf_value < pred_old_next_value (range check)
	/// - Constraints 1–2: mask => pred_new_next == leaf
	pub fn connect_link_constraints<H, F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		// Constraint 5: range check
		inclusion(
			builder,
			&self.pred_value.elements,
			&self.leaf_value.elements,
			&self.pred_old_next_value.elements,
			&self.u,
			&self.v,
			&self.c_ax,
			&self.c_xb,
		);

		// Constraints 1–2: mask => pred_new_next == leaf
		Self::connect_if(
			builder,
			self.mask,
			self.pred_new_next_index,
			self.leaf_index,
		);
		Self::connect_hash_if(
			builder,
			self.mask,
			self.pred_new_next_value,
			self.leaf_value,
		);
	}

	/// Transition constraints between this link (i) and the next link (i+1).
	///
	/// - Constraint 17: leaf_index[i] + 1 == leaf_index[i+1]
	/// - Combined constraints 6/15 and 7/16 via select on next.mask
	/// - Chaining constraints 9–14 via connect_if with !next.mask
	pub fn connect_transition_constraints<F, const D: usize>(
		&self,
		builder: &mut CircuitBuilder<F, D>,
		next: &BatchInsertionLinkTargets,
	) where
		F: Field + RichField + Extendable<D>,
	{
		let one = builder.one();

		// Constraint 17: leaf_index[i] + 1 == leaf_index[i+1]
		let idx_plus_one = builder.add(self.leaf_index, one);
		builder.connect(idx_plus_one, next.leaf_index);

		// Constraint 6/15: leaf_next_index == select(next.mask, pred_old_next_index,
		// next.leaf_index)
		let expected_next_idx =
			builder.select(next.mask, self.pred_old_next_index, next.leaf_index);
		builder.connect(self.leaf_next_index, expected_next_idx);

		// Constraint 7/16: leaf_next_value == select(next.mask, pred_old_next_value,
		// next.leaf_value)
		let expected_next_val = Self::select_hash(
			builder,
			next.mask,
			self.pred_old_next_value,
			next.leaf_value,
		);
		builder.connect_hashes(self.leaf_next_value, expected_next_val);

		// Constraints 9–14: when !next.mask, pred fields must match
		let not_mask = builder.not(next.mask);

		// Constraint 9: pred_path
		for l in 0..self.pred_path.len() {
			Self::connect_if(
				builder,
				not_mask,
				self.pred_path[l].target,
				next.pred_path[l].target,
			);
		}

		// Constraint 10: pred_value
		Self::connect_hash_if(builder, not_mask, self.pred_value, next.pred_value);
		// Constraint 11: pred_new_next_value
		Self::connect_hash_if(
			builder,
			not_mask,
			self.pred_new_next_value,
			next.pred_new_next_value,
		);
		// Constraint 12: pred_new_next_index
		Self::connect_if(
			builder,
			not_mask,
			self.pred_new_next_index,
			next.pred_new_next_index,
		);
		// Constraint 13: pred_old_next_value
		Self::connect_hash_if(
			builder,
			not_mask,
			self.pred_old_next_value,
			next.pred_old_next_value,
		);
		// Constraint 14: pred_old_next_index
		Self::connect_if(
			builder,
			not_mask,
			self.pred_old_next_index,
			next.pred_old_next_index,
		);
	}

	/// Constraint 18: mask == true (first link must be a chain lead).
	pub fn connect_first_link<F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		F: Field + RichField + Extendable<D>,
	{
		let one = builder.one();
		builder.connect(self.mask.target, one);
	}

	/// Constraints 19–20: leaf_next == pred_old_next (last link closes the chain).
	pub fn connect_last_link<F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		F: Field + RichField + Extendable<D>,
	{
		builder.connect(self.leaf_next_index, self.pred_old_next_index);
		builder.connect_hashes(self.leaf_next_value, self.pred_old_next_value);
	}

	// ================================================================
	// Phase C: leaf hash
	// ================================================================

	/// Computes the leaf node hash: H(leaf_value, leaf_next_index, leaf_next_value).
	pub fn leaf_hash_circuit<H, F, const D: usize>(
		&self,
		builder: &mut CircuitBuilder<F, D>,
	) -> HashOutTarget
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
		H::commit_node_circuit(
			builder,
			self.leaf_value,
			self.leaf_next_index,
			self.leaf_next_value,
		)
	}

	// ================================================================
	// Witness
	// ================================================================

	/// Populates all witnesses for this link from a native `BatchInsertionLink`.
	pub fn set<H, F>(
		&self,
		pw: &mut PartialWitness<F>,
		link: &super::BatchInsertionLink<H>,
	) -> Result<()>
	where
		H: MerkleHash,
		H::Digest: ToHashOut<F>,
		F: Field + PrimeField64,
	{
		pw.set_bool_target(self.mask, link.mask)?;

		pw.set_target(
			self.leaf_index,
			F::from_canonical_u64(link.leaf_index as u64),
		)?;
		pw.set_hash_target(self.leaf_value, link.leaf_value.to_hash_out())?;
		pw.set_target(
			self.leaf_next_index,
			F::from_canonical_u64(link.leaf_next_index as u64),
		)?;
		pw.set_hash_target(self.leaf_next_value, link.leaf_next_value.to_hash_out())?;

		// Predecessor path bits
		for (i, bit_target) in self.pred_path.iter().enumerate() {
			pw.set_bool_target(*bit_target, ((link.pred_path >> i) & 1) == 1)?;
		}

		pw.set_hash_target(self.pred_value, link.pred_value.to_hash_out())?;
		pw.set_target(
			self.pred_old_next_index,
			F::from_canonical_u64(link.pred_old_next_index as u64),
		)?;
		pw.set_hash_target(
			self.pred_old_next_value,
			link.pred_old_next_value.to_hash_out(),
		)?;
		pw.set_target(
			self.pred_new_next_index,
			F::from_canonical_u64(link.pred_new_next_index as u64),
		)?;
		pw.set_hash_target(
			self.pred_new_next_value,
			link.pred_new_next_value.to_hash_out(),
		)?;

		// Predecessor siblings
		for (i, sibling_target) in self.pred_old_siblings.iter().enumerate() {
			pw.set_hash_target(*sibling_target, link.pred_old_siblings[i].to_hash_out())?;
		}
		for (i, sibling_target) in self.pred_new_siblings.iter().enumerate() {
			pw.set_hash_target(*sibling_target, link.pred_new_siblings[i].to_hash_out())?;
		}

		// Range-check witnesses
		populate_inclusion_witness(
			pw,
			&link.pred_value.to_hash_out().elements,
			&link.leaf_value.to_hash_out().elements,
			&link.pred_old_next_value.to_hash_out().elements,
			&self.u,
			&self.v,
			&self.c_ax,
			&self.c_xb,
		)?;

		Ok(())
	}

	// ================================================================
	// Low-level helpers
	// ================================================================

	/// Enforces `cond => (a == b)` as `cond * (a - b) == 0`.
	#[inline]
	fn connect_if<F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		cond: BoolTarget,
		a: Target,
		b: Target,
	) where
		F: Field + RichField + Extendable<D>,
	{
		let diff = builder.sub(a, b);
		let product = builder.mul(cond.target, diff);
		builder.assert_zero(product);
	}

	/// Enforces `cond => (a == b)` element-wise for HashOutTargets.
	#[inline]
	fn connect_hash_if<F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		cond: BoolTarget,
		a: HashOutTarget,
		b: HashOutTarget,
	) where
		F: Field + RichField + Extendable<D>,
	{
		for i in 0..HASH_SIZE {
			Self::connect_if(builder, cond, a.elements[i], b.elements[i]);
		}
	}

	/// Selects between two HashOutTargets based on a boolean condition.
	#[inline]
	fn select_hash<F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		cond: BoolTarget,
		if_true: HashOutTarget,
		if_false: HashOutTarget,
	) -> HashOutTarget
	where
		F: Field + RichField + Extendable<D>,
	{
		HashOutTarget {
			elements: core::array::from_fn(|i| {
				builder.select(cond, if_true.elements[i], if_false.elements[i])
			}),
		}
	}

	/// Computes a Merkle root from a leaf hash and its full-depth authentication path.
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

		for (level, (sibling, &dir)) in siblings.iter().zip(path.iter()).enumerate() {
			if level == depth - 1 {
				current =
					Self::hash_parent_root::<H, F, D>(builder, current, *sibling, dir, num_leaves);
			} else {
				current = H::hash_2_to_1_circuit(builder, current, *sibling, dir);
			}
		}
		current
	}

	/// Hashes a parent node at the root level, committing the tree size.
	#[inline]
	fn hash_parent_root<H, F, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		current: HashOutTarget,
		sibling: HashOutTarget,
		dir: BoolTarget,
		num_leaves: Target,
	) -> HashOutTarget
	where
		H: MerkleHashCircuit<F, D>,
		F: Field + RichField + Extendable<D>,
	{
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
		H::hash_root_circuit(builder, num_leaves, left, right)
	}
}

#[cfg(test)]
mod test {
	use std::time::Instant;

	use anyhow::Result;
	use plonky2::{
		field::{
			goldilocks_field::GoldilocksField,
			types::{Field, PrimeField64},
		},
		iop::witness::{PartialWitness, WitnessWrite},
		plonk::{
			circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
			config::PoseidonGoldilocksConfig,
		},
	};

	use super::BatchNullifierInsertProofTargets;
	use crate::tree::{
		NullifierInsertProof, NullifierTree,
		hasher::{Hash, NewFromU64},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = GoldilocksField;

	const DEPTH: usize = 4;
	const BATCH_SIZE: usize = 4;

	/// Helper: builds a tree, batch-inserts, and runs the full circuit proof.
	fn run_batch_circuit(initial_leaves: &[u64], batch_leaves: &[u64]) -> Result<()> {
		let mut tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(DEPTH);
		for &v in initial_leaves {
			let leaf: Hash = Hash::new_from_u64(v);
			let proof: NullifierInsertProof<Hash> = tree.insert(leaf)?;
			assert!(proof.verify());
		}
		tree.verify()?;

		let leaves: Vec<Hash> = batch_leaves
			.iter()
			.map(|&v| Hash::new_from_u64(v))
			.collect();
		let batch_proof = tree.insert_batch(leaves)?;
		tree.verify()?;
		assert!(batch_proof.verify());

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let targets = BatchNullifierInsertProofTargets::new(&mut builder, DEPTH, BATCH_SIZE);
		targets.connect::<Hash, F, D>(&mut builder);

		let mut pw = PartialWitness::new();
		targets.set::<Hash, F, DEPTH>(&mut pw, &batch_proof)?;

		let data = builder.build::<C>();
		let circuit_proof = data.prove(pw)?;
		data.verify(circuit_proof)?;

		Ok(())
	}

	#[test]
	fn test_batch_nullifier_full() -> Result<()> {
		run_batch_circuit(&[5, 15, 12, 30, 7, 13, 25], &[6, 14, 26, 27])
	}

	/// Test with all-masked predecessors (no chaining).
	#[test]
	fn test_batch_nullifier_all_masked() -> Result<()> {
		run_batch_circuit(&[10, 20, 30, 40, 50, 60, 70], &[15, 25, 35, 45])
	}

	/// Test with max chaining (single masked predecessor).
	#[test]
	fn test_batch_nullifier_max_chaining() -> Result<()> {
		run_batch_circuit(&[10, 100, 200, 300, 400, 500, 600], &[20, 30, 40, 50])
	}

	/// Generates `count` unique random-looking Hash values using a multiplicative hash.
	/// Values are guaranteed unique and well-spread across the field.
	fn random_hashes(seed: u64, count: usize) -> Vec<Hash> {
		use std::collections::HashSet;
		let mut seen = HashSet::new();
		let mut hashes = Vec::with_capacity(count);
		let mut state = seed;
		while hashes.len() < count {
			// Multiplicative hash (Knuth's)
			state = state
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			let a = state;
			state = state
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			let b = state;
			state = state
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			let c = state;
			state = state
				.wrapping_mul(6364136223846793005)
				.wrapping_add(1442695040888963407);
			let d = state;
			// Ensure uniqueness by canonical form
			let h = Hash::new([
				F::from_noncanonical_u64(a),
				F::from_noncanonical_u64(b),
				F::from_noncanonical_u64(c),
				F::from_noncanonical_u64(d),
			]);
			if seen.insert(h.0.map(|f| f.to_canonical_u64())) {
				hashes.push(h);
			}
		}
		hashes
	}

	/// Parameterized test with random hashes.
	///
	/// `DEPTH` and `BATCH_SIZE` are const generics for the circuit.
	/// `num_initial` controls how many leaves are inserted before the batch.
	fn run_random_batch_circuit<const TREE_DEPTH: usize, const BATCH: usize>(
		num_initial: usize,
		seed: u64,
	) -> Result<()> {
		// start_index = num_initial + 1 (sentinel at index 0)
		let start_index = num_initial + 1;
		assert!(
			start_index + BATCH <= (1 << TREE_DEPTH),
			"tree capacity exceeded"
		);
		assert!(
			start_index.is_multiple_of(BATCH),
			"start_index (num_initial + 1) must be aligned to BATCH"
		);

		let all_hashes = random_hashes(seed, num_initial + BATCH);
		let initial_hashes = &all_hashes[..num_initial];
		let batch_hashes = &all_hashes[num_initial..];

		let mut tree: NullifierTree<Hash> = NullifierTree::<Hash>::new(TREE_DEPTH);
		for &h in initial_hashes {
			let proof = tree.insert(h)?;
			assert!(proof.verify());
		}
		tree.verify()?;

		let batch_proof = tree.insert_batch(batch_hashes.to_vec())?;
		tree.verify()?;
		assert!(batch_proof.verify());

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let targets = BatchNullifierInsertProofTargets::new(&mut builder, TREE_DEPTH, BATCH);
		targets.connect::<Hash, F, D>(&mut builder);

		let mut pw = PartialWitness::new();
		targets.set::<Hash, F, TREE_DEPTH>(&mut pw, &batch_proof)?;

		let data = builder.build::<C>();
		let now = Instant::now();
		let circuit_proof = data.prove(pw)?;
		println!("prove: {:?}", now.elapsed());

		println!("\nPublic inputs: {}", circuit_proof.public_inputs.len());
		println!("Proof size: {}KB", circuit_proof.to_bytes().len() >> 10);

		data.verify(circuit_proof)?;

		Ok(())
	}

	#[test]
	fn test_batch_nullifier_random_d8_b8_n63() -> Result<()> {
		run_random_batch_circuit::<8, 8>(63, 42)
	}

	#[test]
	fn test_batch_nullifier_random_d8_b4_n15() -> Result<()> {
		run_random_batch_circuit::<8, 4>(15, 123)
	}

	#[test]
	fn test_batch_nullifier_random_d6_b2_n7() -> Result<()> {
		run_random_batch_circuit::<6, 2>(7, 7)
	}

	#[test]
	fn test_batch_nullifier_random_d32_b128_n16383() -> Result<()> {
		run_random_batch_circuit::<32, 1024>(16383, 7)
	}

	// ================================================================
	// Low-level BatchInsertionLinkTargets unit tests
	// ================================================================

	use super::{BatchInsertProof, BatchInsertionLinkTargets};
	use crate::tree::hasher::{MerkleHash, ToHashOut};

	/// Builds a valid batch proof for low-level tests (depth=4, batch=4).
	fn make_batch_proof() -> BatchInsertProof<Hash> {
		let mut tree = NullifierTree::<Hash>::new(DEPTH);
		for &v in &[5u64, 15, 12, 30, 7, 13, 25] {
			tree.insert(Hash::new_from_u64(v)).unwrap();
		}
		let leaves = [6u64, 14, 26, 27]
			.iter()
			.map(|&v| Hash::new_from_u64(v))
			.collect();
		let proof = tree.insert_batch(leaves).unwrap();
		assert!(proof.verify());
		proof
	}

	/// Tests connect_link_constraints with valid witness (should prove).
	#[test]
	fn test_link_constraints_valid() -> Result<()> {
		let proof = make_batch_proof();
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let link_targets = BatchInsertionLinkTargets::new(&mut builder, DEPTH);
		link_targets.connect_link_constraints::<Hash, F, D>(&mut builder);

		let mut pw = PartialWitness::new();
		link_targets.set::<Hash, F>(&mut pw, &proof.links[0])?;

		let data = builder.build::<C>();
		let circuit_proof = data.prove(pw)?;
		data.verify(circuit_proof)?;
		Ok(())
	}

	/// Tests connect_pred_old_auth + connect_pred_new_auth with valid witness.
	#[test]
	fn test_link_pred_auth_valid() -> Result<()> {
		let proof = make_batch_proof();
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let link_targets = BatchInsertionLinkTargets::new(&mut builder, DEPTH);
		let start_index = builder.add_virtual_target();
		let old_root_target = builder.add_virtual_hash();
		let mid_root = link_targets.compute_mid_root::<Hash, F, D>(&mut builder, start_index);
		link_targets.connect_pred_old_auth::<Hash, F, D>(
			&mut builder,
			old_root_target,
			start_index,
		);
		link_targets.connect_pred_new_auth::<Hash, F, D>(&mut builder, mid_root, start_index);

		let mut pw = PartialWitness::new();
		link_targets.set::<Hash, F>(&mut pw, &proof.links[0])?;
		pw.set_target(start_index, F::from_canonical_u64(proof.start_index as u64))?;
		pw.set_hash_target(old_root_target, proof.old_root.to_hash_out())?;

		let data = builder.build::<C>();
		let circuit_proof = data.prove(pw)?;
		data.verify(circuit_proof)?;
		Ok(())
	}

	/// Tests connect_pred_old_auth rejects tampered siblings.
	#[test]
	fn test_link_pred_auth_tampered() -> Result<()> {
		let mut proof = make_batch_proof();
		proof.links[0].pred_old_siblings[0] = Hash::new_from_u64(999);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let link_targets = BatchInsertionLinkTargets::new(&mut builder, DEPTH);
		let start_index = builder.add_virtual_target();
		let old_root_target = builder.add_virtual_hash();
		link_targets.connect_pred_old_auth::<Hash, F, D>(
			&mut builder,
			old_root_target,
			start_index,
		);

		let mut pw = PartialWitness::new();
		link_targets.set::<Hash, F>(&mut pw, &proof.links[0])?;
		pw.set_target(start_index, F::from_canonical_u64(proof.start_index as u64))?;
		pw.set_hash_target(old_root_target, proof.old_root.to_hash_out())?;

		let data = builder.build::<C>();
		assert!(data.prove(pw).is_err());
		Ok(())
	}

	/// Tests transition constraints between two consecutive links.
	#[test]
	fn test_link_transition_valid() -> Result<()> {
		let proof = make_batch_proof();
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let link0 = BatchInsertionLinkTargets::new(&mut builder, DEPTH);
		let link1 = BatchInsertionLinkTargets::new(&mut builder, DEPTH);
		link0.connect_transition_constraints(&mut builder, &link1);

		let mut pw = PartialWitness::new();
		link0.set::<Hash, F>(&mut pw, &proof.links[0])?;
		link1.set::<Hash, F>(&mut pw, &proof.links[1])?;

		let data = builder.build::<C>();
		let circuit_proof = data.prove(pw)?;
		data.verify(circuit_proof)?;
		Ok(())
	}

	/// Tests first and last link constraints.
	#[test]
	fn test_link_first_last() -> Result<()> {
		let proof = make_batch_proof();
		let config = CircuitConfig::standard_recursion_config();

		// First link: mask must be true
		let mut builder = CircuitBuilder::<F, D>::new(config.clone());
		let link_targets = BatchInsertionLinkTargets::new(&mut builder, DEPTH);
		link_targets.connect_first_link(&mut builder);

		let mut pw = PartialWitness::new();
		link_targets.set::<Hash, F>(&mut pw, &proof.links[0])?;

		let data = builder.build::<C>();
		let circuit_proof = data.prove(pw)?;
		data.verify(circuit_proof)?;

		// Last link: leaf_next == pred_old_next
		let last = proof.links.last().unwrap();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let link_targets = BatchInsertionLinkTargets::new(&mut builder, DEPTH);
		link_targets.connect_last_link(&mut builder);

		let mut pw = PartialWitness::new();
		link_targets.set::<Hash, F>(&mut pw, last)?;

		let data = builder.build::<C>();
		let circuit_proof = data.prove(pw)?;
		data.verify(circuit_proof)?;

		Ok(())
	}

	/// Tests leaf_hash_circuit matches native leaf_hash.
	#[test]
	fn test_link_leaf_hash() -> Result<()> {
		let proof = make_batch_proof();
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let link_targets = BatchInsertionLinkTargets::new(&mut builder, DEPTH);
		let hash_target = link_targets.leaf_hash_circuit::<Hash, F, D>(&mut builder);
		let expected = builder.add_virtual_hash();
		builder.connect_hashes(hash_target, expected);

		let native_hash = proof.links[0].leaf_hash();

		let mut pw = PartialWitness::new();
		link_targets.set::<Hash, F>(&mut pw, &proof.links[0])?;
		pw.set_hash_target(expected, native_hash.to_hash_out())?;

		let data = builder.build::<C>();
		let circuit_proof = data.prove(pw)?;
		data.verify(circuit_proof)?;
		Ok(())
	}
}
